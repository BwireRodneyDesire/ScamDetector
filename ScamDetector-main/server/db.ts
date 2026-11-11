import { and, desc, eq, gte } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertScamReport,
  InsertScanHistory,
  scamReports,
  scanHistory,
  InsertUser,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;
  const values: InsertUser = { openId: user.openId };
  const updateSet: Record<string, unknown> = {};
  const textFields = ["name", "email", "loginMethod"] as const;
  for (const field of textFields) {
    if (user[field] !== undefined) {
      const value = user[field] ?? null;
      values[field] = value;
      updateSet[field] = value;
    }
  }
  if (user.lastSignedIn !== undefined) {
    values.lastSignedIn = user.lastSignedIn;
    updateSet.lastSignedIn = user.lastSignedIn;
  }
  if (user.role !== undefined) {
    values.role = user.role;
    updateSet.role = user.role;
  } else if (user.openId === ENV.ownerOpenId) {
    values.role = "admin";
    updateSet.role = "admin";
  }
  if (!values.lastSignedIn) values.lastSignedIn = new Date();
  if (!Object.keys(updateSet).length) updateSet.lastSignedIn = new Date();
  await db
    .insert(users)
    .values(values)
    .onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db
    .select()
    .from(users)
    .where(eq(users.openId, openId))
    .limit(1);
  return result[0];
}

export async function listScanHistory(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      id: scanHistory.id,
      url: scanHistory.url,
      verdict: scanHistory.verdict,
      riskScore: scanHistory.riskScore,
      checkedAt: scanHistory.checkedAt,
    })
    .from(scanHistory)
    .where(eq(scanHistory.userId, userId))
    .orderBy(desc(scanHistory.checkedAt))
    .limit(50);
}
export async function addScanHistory(entry: InsertScanHistory) {
  const db = await getDb();
  if (db) await db.insert(scanHistory).values(entry);
}
export async function clearScanHistory(userId: number) {
  const db = await getDb();
  if (db) await db.delete(scanHistory).where(eq(scanHistory.userId, userId));
}
export async function trimScanHistory(userId: number) {
  const db = await getDb();
  if (!db) return;
  const rows = await db
    .select({ id: scanHistory.id })
    .from(scanHistory)
    .where(eq(scanHistory.userId, userId))
    .orderBy(desc(scanHistory.checkedAt));
  for (const row of rows.slice(50))
    await db
      .delete(scanHistory)
      .where(and(eq(scanHistory.id, row.id), eq(scanHistory.userId, userId)));
}

export async function addScamReport(entry: InsertScamReport) {
  const db = await getDb();
  if (db) await db.insert(scamReports).values(entry);
}
export async function hasUserReportedHost(userId: number, urlHost: string) {
  const db = await getDb();
  if (!db) return false;
  return (
    (
      await db
        .select({ id: scamReports.id })
        .from(scamReports)
        .where(
          and(eq(scamReports.userId, userId), eq(scamReports.urlHost, urlHost))
        )
        .limit(1)
    ).length > 0
  );
}
export async function countUserReportsSince(userId: number, since: Date) {
  const db = await getDb();
  if (!db) return 0;
  return (
    await db
      .select({ id: scamReports.id })
      .from(scamReports)
      .where(
        and(eq(scamReports.userId, userId), gte(scamReports.createdAt, since))
      )
  ).length;
}
export async function getCommunityReports(urlHost: string) {
  const db = await getDb();
  if (!db)
    return {
      reportCount: 0,
      userCount: 0,
      categories: [] as Array<{ category: string; count: number }>,
    };
  const rows = await db
    .select({ userId: scamReports.userId, category: scamReports.category })
    .from(scamReports)
    .where(eq(scamReports.urlHost, urlHost));
  const counts = new Map<string, number>();
  for (const row of rows)
    counts.set(row.category, (counts.get(row.category) ?? 0) + 1);
  return {
    reportCount: rows.length,
    userCount: new Set(rows.map(row => row.userId)).size,
    categories: Array.from(counts.entries())
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count),
  };
}
