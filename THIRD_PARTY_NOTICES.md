# Third-party notices

InboxGate includes `go.yaml.in/yaml/v3` v3.0.5.
The upstream project applies the MIT license to files ported from libyaml and the Apache License 2.0 to its remaining files.

## MIT-licensed files

The following notice applies to `apic.go`, `emitterc.go`, `parserc.go`, `readerc.go`, `scannerc.go`, `writerc.go`, `yamlh.go`, and `yamlprivateh.go` in the upstream module.

Copyright (c) 2006-2010 Kirill Simonov

Copyright (c) 2006-2011 Kirill Simonov

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Model Context Protocol Go SDK

InboxGate includes `github.com/modelcontextprotocol/go-sdk` v1.7.0.
The upstream project is undergoing a transition from MIT to Apache License 2.0.
New code and specification contributions are licensed under Apache License 2.0, contributions whose authors have not consented to relicensing remain under MIT, and non-specification documentation is licensed under Creative Commons Attribution 4.0.
The complete transition notice and applicable license texts are available at <https://github.com/modelcontextprotocol/go-sdk/blob/v1.7.0/LICENSE>.

Copyright (c) 2024-2025 Model Context Protocol a Series of LF Projects, LLC.

Apache-2.0 and retained MIT software are provided without warranties or conditions of any kind.
CC-BY-4.0 documentation attribution is retained through this notice and the upstream project link.

## Go JSON Web Token

InboxGate includes `github.com/golang-jwt/jwt/v5` v5.3.1 under the MIT License.

Copyright (c) 2012 Dave Grijalva

Copyright (c) 2021 golang-jwt maintainers

Permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and sell copies when the copyright and permission notice are retained.
The software is provided without warranty, and its authors are not liable for damages arising from its use.

## Go comparison library

InboxGate includes `github.com/google/go-cmp` v0.7.0 under the BSD 3-Clause License.

Copyright (c) 2017 The Go Authors.

Redistribution in source and binary forms is permitted when the copyright notice, conditions, and disclaimer are retained.
Neither Google LLC nor contributor names may be used to endorse derived products without specific prior permission.
The software is provided without warranties, and its authors are not liable for damages arising from its use.

## JSON Schema Go

InboxGate includes `github.com/google/jsonschema-go` v0.4.3 under the MIT License.

Copyright (c) 2025 JSON Schema Go Project Authors

Permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and sell copies when the copyright and permission notice are retained.
The software is provided without warranty, and its authors are not liable for damages arising from its use.

## Segment assembly helpers

InboxGate includes `github.com/segmentio/asm` v1.1.3 under the MIT License.

Copyright (c) 2021 Segment

Permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and sell copies when the copyright and permission notice are retained.
The software is provided without warranty, and its authors are not liable for damages arising from its use.

## Segment encoding library

InboxGate includes `github.com/segmentio/encoding` v0.5.4 under the MIT License.

Copyright (c) 2019 Segment.io, Inc.

Permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and sell copies when the copyright and permission notice are retained.
The software is provided without warranty, and its authors are not liable for damages arising from its use.

## URI Template v3

InboxGate includes `github.com/yosida95/uritemplate/v3` v3.0.2 under the BSD 3-Clause License.

Copyright (c) 2016, Kohei YOSHIDA <https://yosida95.com/>.

Redistribution in source and binary forms is permitted when the copyright notice, conditions, and disclaimer are retained.
Neither the copyright holder nor contributor names may be used to endorse derived products without specific prior permission.
The software is provided without warranties, and its authors are not liable for damages arising from its use.

## Go synchronization, system, time, and tools modules

InboxGate includes `golang.org/x/sync` v0.20.0, `golang.org/x/sys` v0.41.0, `golang.org/x/time` v0.15.0, and `golang.org/x/tools` v0.42.0 under the BSD 3-Clause License.

Copyright 2009 The Go Authors.

Redistribution in source and binary forms is permitted when the copyright notice, conditions, and disclaimer are retained.
Neither Google LLC nor contributor names may be used to endorse derived products without specific prior permission.
The software is provided without warranties, and its authors are not liable for damages arising from its use.

## YAML Apache-licensed files

The following notice applies to the remaining files in `go.yaml.in/yaml/v3` v3.0.5.

Copyright (c) 2011-2019 Canonical Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License.
You may obtain a copy of the License at <https://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

The upstream `NOTICE` file also states:

Copyright 2011-2016 Canonical Ltd.

## Go OAuth 2.0

InboxGate includes `golang.org/x/oauth2` v0.36.0 under the BSD 3-Clause License.

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the copyright notice, conditions, and disclaimer are retained.
Neither Google LLC nor contributor names may be used to endorse derived products without specific prior permission.
The software is provided without warranties, and its authors are not liable for damages arising from its use.

## Google Compute metadata module

The OAuth module requires `cloud.google.com/go/compute/metadata` v0.3.0.
That module is licensed under the Apache License 2.0, available at <https://www.apache.org/licenses/LICENSE-2.0>.
It is provided without warranties or conditions of any kind.

## Turso serverless Go driver

InboxGate includes `turso.tech/database/tursogo-serverless` v0.0.0-20260817122138-24adc316cdc4.
InboxGate distributes modified local source from upstream commit `24adc316cdc4ebf93d90b94dbfda727195540497` at `third_party/tursogo-serverless`.
The semantic modifications are limited to `driver.go` and `session.go` and make stream close bounded, context-aware, error-propagating, idempotent, and joined.
The copied `README.md` and `encryption_header_test.go` normalize exactly four prohibited punctuation characters to plain hyphens without changing executable or test behavior.
The machine-readable provenance and exact file hashes are recorded in `third_party/tursogo-serverless/INBOXGATE_PROVENANCE.json`.
The following MIT license applies to that upstream module.

Copyright 2024 the Turso authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
