CREATE TABLE "affected_packages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_record_id" uuid NOT NULL,
	"package_id" uuid NOT NULL,
	"relationship" text DEFAULT 'affected' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "affected_products" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_record_id" uuid NOT NULL,
	"product_id" uuid NOT NULL,
	"relationship" text DEFAULT 'affected' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ecosystems" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"version_scheme" text,
	"package_url_type" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "external_references" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"url" text NOT NULL,
	"title" text,
	"kind" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "identifiers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"value" text NOT NULL,
	"kind" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "package_products" (
	"package_id" uuid NOT NULL,
	"product_id" uuid NOT NULL,
	"relationship" text DEFAULT 'distributed_as' NOT NULL,
	"confidence" text DEFAULT 'medium' NOT NULL,
	"source" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "package_products_package_id_product_id_pk" PRIMARY KEY("package_id","product_id")
);
--> statement-breakpoint
CREATE TABLE "package_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"package_id" uuid NOT NULL,
	"version" text NOT NULL,
	"normalized_version" text,
	"released_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "packages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ecosystem_id" uuid NOT NULL,
	"name" text NOT NULL,
	"purl" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "products" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"vendor" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "source_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_id" uuid NOT NULL,
	"external_id" text NOT NULL,
	"url" text,
	"schema_version" text,
	"source_published_at" timestamp with time zone,
	"source_modified_at" timestamp with time zone,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL,
	"raw" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "version_ranges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"affected_package_id" uuid NOT NULL,
	"range_type" text,
	"introduced" text,
	"fixed" text,
	"last_affected" text,
	"limit" text,
	"expression" text,
	"repo" text,
	"raw" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerabilities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"primary_identifier" text,
	"title" text,
	"summary" text,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerability_identifiers" (
	"vulnerability_id" uuid NOT NULL,
	"identifier_id" uuid NOT NULL,
	"relationship" text DEFAULT 'alias' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulnerability_identifiers_vulnerability_id_identifier_id_pk" PRIMARY KEY("vulnerability_id","identifier_id")
);
--> statement-breakpoint
CREATE TABLE "vulnerability_record_identifiers" (
	"vulnerability_record_id" uuid NOT NULL,
	"identifier_id" uuid NOT NULL,
	"relationship" text DEFAULT 'alias' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulnerability_record_identifiers_vulnerability_record_id_identifier_id_pk" PRIMARY KEY("vulnerability_record_id","identifier_id")
);
--> statement-breakpoint
CREATE TABLE "vulnerability_record_references" (
	"vulnerability_record_id" uuid NOT NULL,
	"reference_id" uuid NOT NULL,
	"relationship" text DEFAULT 'references' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulnerability_record_references_vulnerability_record_id_reference_id_pk" PRIMARY KEY("vulnerability_record_id","reference_id")
);
--> statement-breakpoint
CREATE TABLE "vulnerability_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_record_id" uuid NOT NULL,
	"vulnerability_id" uuid,
	"record_id" text NOT NULL,
	"summary" text,
	"details" text,
	"published_at" timestamp with time zone,
	"modified_at" timestamp with time zone,
	"withdrawn_at" timestamp with time zone,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "affected_packages" ADD CONSTRAINT "affected_packages_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_packages" ADD CONSTRAINT "affected_packages_package_id_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."packages"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "package_products" ADD CONSTRAINT "package_products_package_id_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "package_products" ADD CONSTRAINT "package_products_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "package_versions" ADD CONSTRAINT "package_versions_package_id_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "packages" ADD CONSTRAINT "packages_ecosystem_id_ecosystems_id_fk" FOREIGN KEY ("ecosystem_id") REFERENCES "public"."ecosystems"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "source_records" ADD CONSTRAINT "source_records_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD CONSTRAINT "version_ranges_affected_package_id_affected_packages_id_fk" FOREIGN KEY ("affected_package_id") REFERENCES "public"."affected_packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_identifiers" ADD CONSTRAINT "vulnerability_identifiers_vulnerability_id_vulnerabilities_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerabilities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_identifiers" ADD CONSTRAINT "vulnerability_identifiers_identifier_id_identifiers_id_fk" FOREIGN KEY ("identifier_id") REFERENCES "public"."identifiers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_identifiers" ADD CONSTRAINT "vulnerability_record_identifiers_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_identifiers" ADD CONSTRAINT "vulnerability_record_identifiers_identifier_id_identifiers_id_fk" FOREIGN KEY ("identifier_id") REFERENCES "public"."identifiers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_references" ADD CONSTRAINT "vulnerability_record_references_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_references" ADD CONSTRAINT "vulnerability_record_references_reference_id_external_references_id_fk" FOREIGN KEY ("reference_id") REFERENCES "public"."external_references"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_records" ADD CONSTRAINT "vulnerability_records_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_records" ADD CONSTRAINT "vulnerability_records_vulnerability_id_vulnerabilities_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerabilities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "affected_packages_record_package_idx" ON "affected_packages" USING btree ("vulnerability_record_id","package_id");--> statement-breakpoint
CREATE INDEX "affected_packages_package_idx" ON "affected_packages" USING btree ("package_id");--> statement-breakpoint
CREATE INDEX "affected_packages_record_idx" ON "affected_packages" USING btree ("vulnerability_record_id");--> statement-breakpoint
CREATE UNIQUE INDEX "affected_products_record_product_idx" ON "affected_products" USING btree ("vulnerability_record_id","product_id");--> statement-breakpoint
CREATE INDEX "affected_products_product_idx" ON "affected_products" USING btree ("product_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ecosystems_slug_idx" ON "ecosystems" USING btree ("slug");--> statement-breakpoint
CREATE UNIQUE INDEX "external_references_url_idx" ON "external_references" USING btree ("url");--> statement-breakpoint
CREATE UNIQUE INDEX "identifiers_value_idx" ON "identifiers" USING btree ("value");--> statement-breakpoint
CREATE INDEX "identifiers_kind_idx" ON "identifiers" USING btree ("kind");--> statement-breakpoint
CREATE INDEX "package_products_product_idx" ON "package_products" USING btree ("product_id");--> statement-breakpoint
CREATE UNIQUE INDEX "package_versions_package_version_idx" ON "package_versions" USING btree ("package_id","version");--> statement-breakpoint
CREATE INDEX "package_versions_package_idx" ON "package_versions" USING btree ("package_id");--> statement-breakpoint
CREATE UNIQUE INDEX "packages_ecosystem_name_idx" ON "packages" USING btree ("ecosystem_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "packages_purl_idx" ON "packages" USING btree ("purl");--> statement-breakpoint
CREATE INDEX "packages_name_idx" ON "packages" USING btree ("name");--> statement-breakpoint
CREATE UNIQUE INDEX "products_slug_idx" ON "products" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "products_name_idx" ON "products" USING btree ("name");--> statement-breakpoint
CREATE UNIQUE INDEX "source_records_source_external_idx" ON "source_records" USING btree ("source_id","external_id");--> statement-breakpoint
CREATE INDEX "source_records_source_idx" ON "source_records" USING btree ("source_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sources_slug_idx" ON "sources" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "version_ranges_affected_package_idx" ON "version_ranges" USING btree ("affected_package_id");--> statement-breakpoint
CREATE INDEX "version_ranges_fixed_idx" ON "version_ranges" USING btree ("fixed");--> statement-breakpoint
CREATE UNIQUE INDEX "vulnerabilities_primary_identifier_idx" ON "vulnerabilities" USING btree ("primary_identifier");--> statement-breakpoint
CREATE UNIQUE INDEX "vulnerability_records_source_record_idx" ON "vulnerability_records" USING btree ("source_record_id");--> statement-breakpoint
CREATE INDEX "vulnerability_records_vulnerability_idx" ON "vulnerability_records" USING btree ("vulnerability_id");--> statement-breakpoint
CREATE INDEX "vulnerability_records_record_id_idx" ON "vulnerability_records" USING btree ("record_id");