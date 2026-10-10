CREATE TABLE "eas" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"desc" text DEFAULT '' NOT NULL,
	"logo" text DEFAULT '' NOT NULL,
	"bg" text DEFAULT '' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "licenses" (
	"key" text PRIMARY KEY,
	"ea_id" text NOT NULL,
	"days" integer DEFAULT 0 NOT NULL,
	"note" text DEFAULT '' NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"activated_by" text,
	"activated_at" timestamp,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"email" text NOT NULL UNIQUE,
	"name" text DEFAULT '' NOT NULL,
	"password_hash" text NOT NULL,
	"settings" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
