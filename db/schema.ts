import { pgTable, serial, text, timestamp, integer, boolean, jsonb } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial().primaryKey(),
  email: text().notNull().unique(),
  name: text().notNull().default(""),
  passwordHash: text("password_hash").notNull(),
  settings: jsonb().notNull().default({}),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

// Expert Advisors (bots) the admin publishes to licensed users
export const eas = pgTable("eas", {
  id: text().primaryKey(),
  name: text().notNull(),
  desc: text().notNull().default(""),
  logo: text().notNull().default(""),
  bg: text().notNull().default(""),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

// Licenses keep their eaId after an EA is deleted so the admin list can show "(deleted)"
export const licenses = pgTable("licenses", {
  key: text().primaryKey(),
  eaId: text("ea_id").notNull(),
  days: integer().notNull().default(0),
  note: text().notNull().default(""),
  revoked: boolean().notNull().default(false),
  activatedBy: text("activated_by"),
  activatedAt: timestamp("activated_at"),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});
