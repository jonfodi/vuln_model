CREATE TABLE "affected_software_identifiers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"affected_package_id" uuid,
	"affected_product_id" uuid,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"raw" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "affected_software_identifiers_one_target_chk" CHECK (("affected_software_identifiers"."affected_package_id" is not null and "affected_software_identifiers"."affected_product_id" is null) or ("affected_software_identifiers"."affected_package_id" is null and "affected_software_identifiers"."affected_product_id" is not null))
);
--> statement-breakpoint
CREATE TABLE "ecosystem_aliases" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ecosystem_id" uuid NOT NULL,
	"alias" text NOT NULL,
	"alias_kind" text NOT NULL,
	"scope" text,
	"source" text,
	"raw" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerability_record_relationships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_record_id" uuid NOT NULL,
	"source_record_id" uuid NOT NULL,
	"related_identifier_id" uuid NOT NULL,
	"relationship" text NOT NULL,
	"raw" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DROP INDEX "affected_packages_record_package_idx";--> statement-breakpoint
DROP INDEX "affected_products_record_product_idx";--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "source_index" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "default_status" text;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "platforms" jsonb;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "modules" jsonb;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "repo" text;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD COLUMN "raw" jsonb;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "source_index" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "default_status" text;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "platforms" jsonb;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "modules" jsonb;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "program_files" jsonb;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "program_routines" jsonb;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "repo" text;--> statement-breakpoint
ALTER TABLE "affected_products" ADD COLUMN "raw" jsonb;--> statement-breakpoint
ALTER TABLE "cvss_metric_details" ADD COLUMN "raw" jsonb;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD COLUMN "affected_package_id" uuid;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD COLUMN "affected_product_id" uuid;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD COLUMN "raw" jsonb;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "source_index" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "status" text;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "version" text;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "version_type" text;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "less_than" text;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "less_than_or_equal" text;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "changes" jsonb;--> statement-breakpoint
ALTER TABLE "vulnerability_record_references" ADD COLUMN "source_name" text;--> statement-breakpoint
ALTER TABLE "vulnerability_record_references" ADD COLUMN "tags" jsonb;--> statement-breakpoint
ALTER TABLE "vulnerability_record_references" ADD COLUMN "raw" jsonb;--> statement-breakpoint
ALTER TABLE "affected_software_identifiers" ADD CONSTRAINT "affected_software_identifiers_affected_package_id_affected_packages_id_fk" FOREIGN KEY ("affected_package_id") REFERENCES "public"."affected_packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_software_identifiers" ADD CONSTRAINT "affected_software_identifiers_affected_product_id_affected_products_id_fk" FOREIGN KEY ("affected_product_id") REFERENCES "public"."affected_products"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ecosystem_aliases" ADD CONSTRAINT "ecosystem_aliases_ecosystem_id_ecosystems_id_fk" FOREIGN KEY ("ecosystem_id") REFERENCES "public"."ecosystems"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_relationships" ADD CONSTRAINT "vulnerability_record_relationships_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_relationships" ADD CONSTRAINT "vulnerability_record_relationships_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_relationships" ADD CONSTRAINT "vulnerability_record_relationships_related_identifier_id_identifiers_id_fk" FOREIGN KEY ("related_identifier_id") REFERENCES "public"."identifiers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "affected_software_identifiers_package_idx" ON "affected_software_identifiers" USING btree ("affected_package_id");--> statement-breakpoint
CREATE INDEX "affected_software_identifiers_product_idx" ON "affected_software_identifiers" USING btree ("affected_product_id");--> statement-breakpoint
CREATE INDEX "affected_software_identifiers_kind_value_idx" ON "affected_software_identifiers" USING btree ("kind","value");--> statement-breakpoint
CREATE UNIQUE INDEX "ecosystem_aliases_alias_idx" ON "ecosystem_aliases" USING btree ("alias","alias_kind","scope");--> statement-breakpoint
CREATE INDEX "ecosystem_aliases_ecosystem_idx" ON "ecosystem_aliases" USING btree ("ecosystem_id");--> statement-breakpoint
CREATE UNIQUE INDEX "vulnerability_record_relationships_unique_idx" ON "vulnerability_record_relationships" USING btree ("vulnerability_record_id","related_identifier_id","relationship");--> statement-breakpoint
CREATE INDEX "vulnerability_record_relationships_related_idx" ON "vulnerability_record_relationships" USING btree ("related_identifier_id");--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD CONSTRAINT "severity_metrics_affected_package_id_affected_packages_id_fk" FOREIGN KEY ("affected_package_id") REFERENCES "public"."affected_packages"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD CONSTRAINT "severity_metrics_affected_product_id_affected_products_id_fk" FOREIGN KEY ("affected_product_id") REFERENCES "public"."affected_products"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "affected_packages_record_package_source_idx" ON "affected_packages" USING btree ("vulnerability_record_id","package_id","source_index");--> statement-breakpoint
CREATE UNIQUE INDEX "affected_products_record_product_source_idx" ON "affected_products" USING btree ("vulnerability_record_id","product_id","source_index");--> statement-breakpoint
CREATE INDEX "affected_products_record_idx" ON "affected_products" USING btree ("vulnerability_record_id");--> statement-breakpoint
CREATE INDEX "severity_metrics_affected_package_idx" ON "severity_metrics" USING btree ("affected_package_id");--> statement-breakpoint
CREATE INDEX "severity_metrics_affected_product_idx" ON "severity_metrics" USING btree ("affected_product_id");