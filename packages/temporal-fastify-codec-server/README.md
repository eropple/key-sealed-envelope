# @eropple/temporal-fastify-codec-server

A Fastify plugin that serves a Temporal.io `PayloadCodec` over HTTP.

This plugin provides a simple way to expose a `PayloadCodec` from the Temporal SDK as a web service. It is useful for scenarios where a remote system needs to encode or decode Temporal payloads without having direct access to the codec implementation, such as in a polyglot environment or for a remote UI.

## Installation

```bash
pnpm add @eropple/temporal-fastify-codec-server
```

## Usage

Register the plugin with your Fastify instance and provide it with a configured `PayloadCodec`.

```typescript
import { KeySealedEnvelopeRSACodec } from "@eropple/temporal-payload-codec";
import fastify from "fastify";
import { temporalCodecPlugin } from "@eropple/temporal-fastify-codec-server";

// 1. Create and configure your payload codec
const codec = new KeySealedEnvelopeRSACodec({
  // ... your key configuration
});

// 2. Create a Fastify server
const server = fastify();

// 3. Register the plugin
await server.register(temporalCodecPlugin, {
  codec: codec,
});

// 4. Start the server
await server.listen({ port: 8888 });
```

### Options

- `codec` (required): An instance of a class that implements the Temporal `PayloadCodec` interface.

## API

The plugin exposes two `POST` endpoints for handling payload transformations.

### Payload Format

Both endpoints expect a JSON body with a `payloads` key, which is an array of `JSONPayload` objects. The `metadata` and `data` properties of these payloads should be base64-encoded strings.

```json
{
  "payloads": [
    {
      "metadata": {
        "encoding": "anNvbi9wbGFpbg=="
      },
      "data": "eyJoZWxsbyI6IndvcmxkIn0="
    }
  ]
}
```

### `POST /encode`

Takes an array of decoded `JSONPayload` objects and returns them in their encoded form.

### `POST /decode`

Takes an array of encoded `JSONPayload` objects and returns them in their decoded form.
