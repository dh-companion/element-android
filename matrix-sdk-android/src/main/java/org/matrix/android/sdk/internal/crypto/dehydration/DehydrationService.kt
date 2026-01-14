/*
 * Copyright 2024 The Matrix.org Foundation C.I.C.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matrix.android.sdk.internal.crypto.dehydration

import android.util.Base64
import kotlinx.coroutines.withContext
import org.matrix.android.sdk.api.MatrixCoroutineDispatchers
import org.matrix.android.sdk.api.session.crypto.crosssigning.CrossSigningService
import org.matrix.android.sdk.api.session.securestorage.IntegrityResult
import org.matrix.android.sdk.api.session.securestorage.KeyInfoResult
import org.matrix.android.sdk.api.session.securestorage.KeyRef
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SharedSecretStorageService
import org.matrix.android.sdk.internal.crypto.OlmMachine
import org.matrix.android.sdk.internal.crypto.api.CryptoApi
import org.matrix.android.sdk.internal.crypto.model.rest.DehydratedDeviceEventsRequest
import org.matrix.android.sdk.internal.di.MoshiProvider
import org.matrix.android.sdk.internal.session.SessionScope
import org.matrix.rustcomponents.sdk.crypto.DehydratedDeviceKey
import org.matrix.rustcomponents.sdk.crypto.RehydratedDevice
import retrofit2.HttpException
import timber.log.Timber
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Provider

/**
 * Service for handling device dehydration (MSC3814).
 *
 * Device dehydration allows a user to have a "backup device" that can receive
 * room keys while they have no active devices logged in. When they log in again,
 * the dehydrated device is rehydrated and the room keys are recovered.
 */
@SessionScope
internal class DehydrationService @Inject constructor(
        private val olmMachineProvider: Provider<OlmMachine>,
        private val cryptoApi: CryptoApi,
        private val sharedSecretStorageService: SharedSecretStorageService,
        private val crossSigningServiceProvider: Provider<CrossSigningService>,
        private val coroutineDispatchers: MatrixCoroutineDispatchers,
) {

    companion object {
        /** Secret ID for storing the dehydrated device pickle key in SSSS (MSC3814). */
        const val DEHYDRATED_DEVICE_SECRET_ID = "org.matrix.msc3814"

        /** Display name for the dehydrated device. */
        private const val DEVICE_DISPLAY_NAME = "Backup Device"
    }

    private val olmMachine: OlmMachine
        get() = olmMachineProvider.get()

    /**
     * Run the device dehydration flow.
     *
     * This will:
     * 1. Check if a pickle key exists in secret storage
     * 2. If yes: rehydrate the existing device, process its events, delete it, and create a new one
     * 3. If no: generate a new pickle key, store it, and create a new dehydrated device
     *
     * @param privateKeyData The private key data for accessing secret storage (from recovery key or passphrase)
     */
    suspend fun runDeviceDehydrationFlow(privateKeyData: ByteArray) {
        withContext(coroutineDispatchers.io) {
            try {
                runDeviceDehydrationFlowInternal(privateKeyData)
            } catch (e: Exception) {
                Timber.e(e, "Failed device dehydration flow")
            }
        }
    }

    private suspend fun runDeviceDehydrationFlowInternal(privateKeyData: ByteArray) {
        val defaultKeyResult = sharedSecretStorageService.getDefaultKey()
        val defaultKeyId = when (defaultKeyResult) {
            is KeyInfoResult.Success -> defaultKeyResult.keyInfo.id
            is KeyInfoResult.Error -> {
                Timber.e("No default secret storage key available")
                return
            }
        }

        val keySpec = RawBytesKeySpec(privateKeyData)

        // Check if we have a dehydration pickle key stored
        val hasPickleKey = sharedSecretStorageService.checkShouldBeAbleToAccessSecrets(
                secretNames = listOf(DEHYDRATED_DEVICE_SECRET_ID),
                keyId = defaultKeyId
        ) is IntegrityResult.Success

        if (hasPickleKey) {
            // Retrieve existing pickle key from secret storage
            val base64PickleKey = try {
                sharedSecretStorageService.getSecret(
                        name = DEHYDRATED_DEVICE_SECRET_ID,
                        keyId = defaultKeyId,
                        secretKey = keySpec
                )
            } catch (e: Exception) {
                Timber.e(e, "Failed to retrieve dehydration pickle key from secret storage")
                return
            }

            val pickleKeyData = Base64.decode(base64PickleKey, Base64.NO_WRAP)

            // Try to rehydrate existing device
            try {
                val (deviceId, rehydratedDevice) = rehydrateDevice(pickleKeyData)
                Timber.i("Successfully rehydrated device: $deviceId")

                // Process to-device events from the dehydrated device
                processToDeviceEvents(rehydratedDevice, deviceId)

                // Delete the old dehydrated device
                try {
                    deleteDehydratedDevice()
                    Timber.i("Deleted old dehydrated device")
                } catch (e: Exception) {
                    Timber.w(e, "Failed to delete old dehydrated device, continuing anyway")
                }
            } catch (e: NoDehydratedDeviceException) {
                Timber.i("No dehydrated device available, will create a new one")
            } catch (e: Exception) {
                Timber.e(e, "Failed to rehydrate device")
                return
            }

            // Create a new dehydrated device with the same pickle key
            try {
                dehydrateDevice(pickleKeyData)
                Timber.i("Created new dehydrated device")
            } catch (e: Exception) {
                Timber.e(e, "Failed to create dehydrated device")
            }
        } else {
            // Generate a new pickle key (32 random bytes)
            val pickleKeyData = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val base64PickleKey = Base64.encodeToString(pickleKeyData, Base64.NO_WRAP)

            // Store the pickle key in secret storage
            try {
                sharedSecretStorageService.storeSecret(
                        name = DEHYDRATED_DEVICE_SECRET_ID,
                        secretBase64 = base64PickleKey,
                        keys = listOf(KeyRef(keyId = defaultKeyId, keySpec = keySpec))
                )
                Timber.i("Stored dehydration pickle key in secret storage")
            } catch (e: Exception) {
                Timber.e(e, "Failed to store dehydration pickle key")
                return
            }

            // Create a new dehydrated device
            try {
                dehydrateDevice(pickleKeyData)
                Timber.i("Created new dehydrated device")
            } catch (e: Exception) {
                Timber.e(e, "Failed to create dehydrated device")
            }
        }
    }

    /**
     * Create a new dehydrated device and upload it to the server.
     */
    private suspend fun dehydrateDevice(pickleKeyData: ByteArray) {
        Timber.d("🔐 [Dehydration] Creating dehydrated device...")
        val dehydratedDevices = olmMachine.dehydratedDevices()
        val dehydratedDevice = dehydratedDevices.create()
        Timber.d("🔐 [Dehydration] Device created, generating keys for upload...")

        val request = dehydratedDevice.keysForUpload(
                DEVICE_DISPLAY_NAME,
                DehydratedDeviceKey(pickleKeyData)
        )
        Timber.d("🔐 [Dehydration] Keys generated, body size: ${request.body.length} bytes")

        // Parse the request body and send to server
        val moshi = MoshiProvider.providesMoshi()
        @Suppress("UNCHECKED_CAST")
        val body = moshi.adapter(Map::class.java).fromJson(request.body) as? Map<String, Any>
                ?: throw IllegalStateException("Failed to parse dehydrated device request body")

        Timber.d("🔐 [Dehydration] Parsed body, keys: ${body.keys}")
        Timber.d("🔐 [Dehydration] Sending PUT request to create dehydrated device...")

        val deviceId: String
        try {
            val response = cryptoApi.createDehydratedDevice(body)
            deviceId = response.deviceId
            Timber.i("🔐 [Dehydration] PUT request succeeded, device ID: $deviceId")
        } catch (e: Exception) {
            Timber.e(e, "🔐 [Dehydration] PUT request failed")
            throw e
        }

        // Cross-sign the dehydrated device so other clients will trust it and send room keys to it
        try {
            Timber.d("🔐 [Dehydration] Fetching device keys to make dehydrated device known locally...")
            // Force download our own device keys so the local crypto state knows about the new dehydrated device
            olmMachine.ensureUsersKeys(listOf(olmMachine.userId()), forceDownload = true)
            Timber.d("🔐 [Dehydration] Cross-signing dehydrated device $deviceId...")
            crossSigningServiceProvider.get().trustDevice(deviceId)
            Timber.i("🔐 [Dehydration] Successfully cross-signed dehydrated device $deviceId")
        } catch (e: Exception) {
            Timber.e(e, "🔐 [Dehydration] Failed to cross-sign dehydrated device, it may not receive room keys")
            // Don't throw - the device was created, it just won't be trusted
        }
    }

    /**
     * Retrieve and rehydrate an existing dehydrated device.
     *
     * @return A pair of the device ID and the rehydrated device
     * @throws NoDehydratedDeviceException if no dehydrated device exists
     */
    private suspend fun rehydrateDevice(pickleKeyData: ByteArray): Pair<String, RehydratedDevice> {
        val response = try {
            cryptoApi.getDehydratedDevice()
        } catch (e: HttpException) {
            if (e.code() == 404) {
                throw NoDehydratedDeviceException()
            }
            throw e
        }

        val moshi = MoshiProvider.providesMoshi()
        val deviceDataJson = moshi.adapter(Map::class.java).toJson(response.deviceData)

        val rehydratedDevice = olmMachine.dehydratedDevices().rehydrate(
                DehydratedDeviceKey(pickleKeyData),
                response.deviceId,
                deviceDataJson
        )

        return response.deviceId to rehydratedDevice
    }

    /**
     * Process all to-device events that were sent to the dehydrated device.
     */
    private suspend fun processToDeviceEvents(rehydratedDevice: RehydratedDevice, deviceId: String) {
        var nextBatch: String? = null

        do {
            val request = DehydratedDeviceEventsRequest(nextBatch = nextBatch)
            val response = cryptoApi.getDehydratedDeviceEvents(deviceId, request)

            if (response.events.isNotEmpty()) {
                val moshi = MoshiProvider.providesMoshi()
                val eventsJson = moshi.adapter(List::class.java).toJson(response.events)
                rehydratedDevice.receiveEvents(eventsJson)
                Timber.d("Processed ${response.events.size} to-device events from dehydrated device")
            }

            nextBatch = response.nextBatch
        } while (response.events.isNotEmpty())
    }

    /**
     * Delete the current dehydrated device from the server.
     */
    private suspend fun deleteDehydratedDevice() {
        cryptoApi.deleteDehydratedDevice()
    }

    /**
     * Check if device dehydration is available (i.e., if we have crypto set up).
     */
    fun isDehydrationAvailable(): Boolean {
        return try {
            olmMachine.dehydratedDevices()
            true
        } catch (e: Exception) {
            false
        }
    }
}

/**
 * Exception thrown when no dehydrated device exists on the server.
 */
internal class NoDehydratedDeviceException : Exception("No dehydrated device available")
