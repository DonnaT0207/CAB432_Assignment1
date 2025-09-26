// memcachedClient.js
import Memcached from "memcached";
import util from "node:util";

const memcachedAddress =
  "n11145862a2.km2jzi.cfg.apse2.cache.amazonaws.com:11211";

export function createMemcachedClient() {
  if (process.env.IS_EC2 !== "true") {
    console.log("Not EC2 → skipping Memcached setup.");
    return null; // 或 undefined
  }

  //   if (process.env.IS_EC2 !== "true") {
  //     console.log("Not EC2 → using fake in-memory cache (Map).");
  //     const store = new Map();

  //     return {
  //       aGet: async (key) => store.get(key) || null,
  //       aSet: async (key, value, ttl) => {
  //         store.set(key, value);
  //         setTimeout(() => store.delete(key), ttl * 1000);
  //       },
  //     };
  //   }

  console.log("Running on EC2 → connecting to ElastiCache Memcached.");
  const memcached = new Memcached(memcachedAddress);

  memcached.aGet = util.promisify(memcached.get);
  memcached.aSet = util.promisify(memcached.set);

  memcached.on("failure", (details) => {
    console.error("Memcached failure:", details);
  });

  return memcached;
}
