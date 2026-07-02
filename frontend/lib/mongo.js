import { MongoClient } from 'mongodb';

const uri = process.env.MONGO_URL;
const dbName = process.env.DB_NAME || 'vibesafe';

if (!uri) {
  console.warn('[mongo] MONGO_URL not set');
}

let client;
let clientPromise;

const g = globalThis;
if (!g.__vibesafe_mongo) {
  if (uri) {
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 4000 });
    g.__vibesafe_mongo = client.connect();
  } else {
    // Return a dummy promise if no mongo configured
    g.__vibesafe_mongo = Promise.resolve({
      db: () => ({
        collection: () => {
          const cursor = {
            sort: () => cursor,
            limit: () => cursor,
            skip: () => cursor,
            toArray: async () => []
          };
          return {
            createIndex: async () => {},
            insertOne: async () => ({ insertedId: 'dummy' }),
            updateOne: async () => ({ matchedCount: 1 }),
            find: () => cursor,
            findOne: async () => null,
            deleteMany: async () => ({ deletedCount: 0 })
          };
        }
      })
    });
  }
}
clientPromise = g.__vibesafe_mongo;

let indexesEnsured = false;
async function ensureIndexes(db) {
  if (indexesEnsured) return;
  try {
    await db.collection('rate_limit_events').createIndex(
      { ts: 1 },
      { expireAfterSeconds: 60 * 60 * 24 }, // auto-purge after 24h
    );
    await db.collection('rate_limit_events').createIndex({ ip: 1, endpoint: 1, ts: -1 });
    await db.collection('waitlist').createIndex({ email: 1 }, { unique: true });
    await db.collection('scans').createIndex({ scan_id: 1 }, { unique: true });
    await db.collection('scans').createIndex({ created_at: 1 });
    indexesEnsured = true;
  } catch (e) {
    // non-fatal
    console.warn('[mongo] index ensure error', e?.message);
  }
}

export async function getDb() {
  const c = await clientPromise;
  const db = c.db(dbName);
  await ensureIndexes(db);
  return db;
}

export function getCollections() {
  return getDb().then((db) => ({
    waitlist: db.collection('waitlist'),
    rateLimitEvents: db.collection('rate_limit_events'),
    scans: db.collection('scans'),
    db,
  }));
}
