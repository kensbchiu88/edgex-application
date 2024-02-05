#
# Copyright (c) 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM golang:1.21-alpine3.17 AS builder

# add git for go modules
RUN apk update && apk add --no-cache make git
WORKDIR /fit-app

COPY go.mod .

RUN go mod tidy

COPY . .

RUN make build

# Next image - Copy built Go binary into new workspace
FROM alpine

LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2023: Intel'

# Turn off secure mode for examples. Not recommended for production
ENV EDGEX_SECURITY_SECRET_STORE=false

COPY --from=builder /fit-app/res /res
COPY --from=builder /fit-app/app-service /fit-app

CMD [ "/fit-app", "-cp=consul.http://edgex-core-consul:8500", "--registry"]
