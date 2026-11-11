import {
  int,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const scanHistory = mysqlTable("scan_history", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  url: varchar("url", { length: 2048 }).notNull(),
  verdict: varchar("verdict", { length: 32 }).notNull(),
  riskScore: int("riskScore").notNull(),
  checkedAt: timestamp("checkedAt").defaultNow().notNull(),
});

export const scamReports = mysqlTable("scam_reports", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  urlHost: varchar("urlHost", { length: 255 }).notNull(),
  category: varchar("category", { length: 64 }).notNull(),
  description: varchar("description", { length: 500 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type ScanHistory = typeof scanHistory.$inferSelect;
export type InsertScanHistory = typeof scanHistory.$inferInsert;
export type ScamReport = typeof scamReports.$inferSelect;
export type InsertScamReport = typeof scamReports.$inferInsert;
