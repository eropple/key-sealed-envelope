import { type Payload, type PayloadCodec } from "@temporalio/common";
import {
  type FastifyInstance,
  type FastifyPluginAsync,
  type FastifyPluginOptions,
} from "fastify";
import fp from "fastify-plugin";

export interface TemporalCodecPluginOptions extends FastifyPluginOptions {
  codec: PayloadCodec;
}

interface JSONPayload {
  metadata?: Record<string, string> | null;
  data?: string | null;
}

interface Body {
  payloads: JSONPayload[];
}

// this is a fairly naive implementation based mostly on the Express example
// that Temporal provides. I'm agnostic on using `Buffer` here instead of more
// standard options, but this should be performant enough and it does work.

function fromJSON({ metadata, data }: JSONPayload): Payload {
  return {
    metadata: metadata
      ? Object.fromEntries(
          Object.entries(metadata).map(([k, v]): [string, Uint8Array] => [
            k,
            Buffer.from(v, "base64"),
          ])
        )
      : null,
    data: data ? Buffer.from(data, "base64") : null,
  } as Payload;
}

function toJSON({ metadata, data }: Payload): JSONPayload {
  return {
    metadata: metadata
      ? Object.fromEntries(
          Object.entries(metadata).map(([k, v]): [string, string] => [
            k,
            Buffer.from(v).toString("base64"),
          ])
        )
      : null,
    data: data ? Buffer.from(data).toString("base64") : null,
  };
}

const plugin: FastifyPluginAsync<TemporalCodecPluginOptions> = async (
  fastify: FastifyInstance,
  options: TemporalCodecPluginOptions
): Promise<void> => {
  const pLog = fastify.log.child({
    plugin: "@eropple/temporal-fastify-codec-server",
  });

  pLog.debug("Initializing temporal codec plugin.");

  if (!options.codec) {
    throw new Error("PayloadCodec not found in options");
  }

  const { codec } = options;

  fastify.post("/decode", async (request, reply) => {
    const rLog = request.log.child({
      plugin: "@eropple/temporal-fastify-codec-server",
      method: "decode",
    });

    try {
      const { payloads: raw } = request.body as Body;
      const encoded = raw.map(fromJSON);
      const decoded = await codec.decode(encoded);
      const payloads = decoded.map(toJSON);
      await reply.send({ payloads });
    } catch (err) {
      rLog.error({ err }, "Error decoding payloads");
      reply.status(500).send({
        error: "Internal server error",
      });
    }
  });

  fastify.post("/encode", async (request, reply) => {
    const rLog = request.log.child({
      plugin: "@eropple/temporal-fastify-codec-server",
      method: "encode",
    });

    try {
      const { payloads: raw } = request.body as Body;
      const decoded = raw.map(fromJSON);
      const encoded = await codec.encode(decoded);
      const payloads = encoded.map(toJSON);
      await reply.send({ payloads });
    } catch (err) {
      rLog.error({ err }, "Error encoding payloads");
      reply.status(500).send({
        error: "Internal server error",
      });
    }
  });

  pLog.info("Temporal codec plugin initialized.");
};

export const temporalCodecPlugin = fp(plugin, {
  fastify: "5.x",
  name: "@eropple/temporal-fastify-codec-server",
});
