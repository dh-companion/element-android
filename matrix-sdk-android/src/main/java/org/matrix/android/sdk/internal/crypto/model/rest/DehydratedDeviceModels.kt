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

package org.matrix.android.sdk.internal.crypto.model.rest

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * Response from PUT /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device
 */
@JsonClass(generateAdapter = true)
internal data class CreateDehydratedDeviceResponse(
        @Json(name = "device_id")
        val deviceId: String
)

/**
 * Response from GET /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device
 */
@JsonClass(generateAdapter = true)
internal data class DehydratedDeviceResponse(
        @Json(name = "device_id")
        val deviceId: String,
        @Json(name = "device_data")
        val deviceData: Map<String, Any>
)

/**
 * Request body for POST /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{deviceId}/events
 */
@JsonClass(generateAdapter = true)
internal data class DehydratedDeviceEventsRequest(
        @Json(name = "next_batch")
        val nextBatch: String? = null
)

/**
 * Response from POST /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{deviceId}/events
 */
@JsonClass(generateAdapter = true)
internal data class DehydratedDeviceEventsResponse(
        @Json(name = "events")
        val events: List<Map<String, Any>> = emptyList(),
        @Json(name = "next_batch")
        val nextBatch: String? = null
)
