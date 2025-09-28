import Memcached from "memcached";
import util from "node:util";
import { CONFIG } from "./index.js";


export function createMemcachedClient() {
  if (process.env.IS_EC2 !== "true") {
    console.log("Not EC2 → skipping Memcached setup.");
    return null; // or undefined
  }

  console.log("Running on EC2 → connecting to ElastiCache Memcached.");
  // const memcached = new Memcached(memcachedAddress);
  const memcached = new Memcached(CONFIG.AWS_CACHE_ENDPOINT);

  memcached.aGet = util.promisify(memcached.get);
  memcached.aSet = util.promisify(memcached.set);

  memcached.on("failure", (details) => {
    console.error("Memcached failure:", details);
  });

  return memcached;
}
