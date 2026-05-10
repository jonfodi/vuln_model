CREATE TABLE "cvss_metric_details" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"severity_metric_id" uuid NOT NULL,
	"cvss_version" text NOT NULL,
	"attack_vector" text,
	"attack_complexity" text,
	"privileges_required" text,
	"user_interaction" text,
	"scope" text,
	"confidentiality_impact" text,
	"integrity_impact" text,
	"availability_impact" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "epss_scores" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_id" uuid,
	"source_record_id" uuid NOT NULL,
	"cve_identifier_id" uuid NOT NULL,
	"score" numeric(7, 6) NOT NULL,
	"percentile" numeric(7, 6) NOT NULL,
	"score_date" date NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kev_entries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_id" uuid,
	"source_record_id" uuid NOT NULL,
	"cve_identifier_id" uuid NOT NULL,
	"known_exploited" boolean DEFAULT true NOT NULL,
	"vendor_project" text,
	"product" text,
	"vulnerability_name" text,
	"short_description" text,
	"date_added" date,
	"due_date" date,
	"required_action" text,
	"known_ransomware_campaign_use" text,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "severity_metrics" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_record_id" uuid NOT NULL,
	"source_record_id" uuid NOT NULL,
	"provider" text,
	"system" text NOT NULL,
	"score" numeric(4, 1),
	"severity" text,
	"vector" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ssvc_assessments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_record_id" uuid NOT NULL,
	"source_record_id" uuid NOT NULL,
	"provider" text,
	"exploitation" text,
	"automatable" text,
	"technical_impact" text,
	"role" text,
	"version" text,
	"assessed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerability_record_weaknesses" (
	"vulnerability_record_id" uuid NOT NULL,
	"weakness_id" uuid NOT NULL,
	"relationship" text DEFAULT 'asserts' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulnerability_record_weaknesses_vulnerability_record_id_weakness_id_pk" PRIMARY KEY("vulnerability_record_id","weakness_id")
);
--> statement-breakpoint
CREATE TABLE "weaknesses" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cwe_id" text NOT NULL,
	"name" text,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "version_ranges" ALTER COLUMN "affected_package_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "version_ranges" ADD COLUMN "affected_product_id" uuid;--> statement-breakpoint
ALTER TABLE "cvss_metric_details" ADD CONSTRAINT "cvss_metric_details_severity_metric_id_severity_metrics_id_fk" FOREIGN KEY ("severity_metric_id") REFERENCES "public"."severity_metrics"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_scores" ADD CONSTRAINT "epss_scores_vulnerability_id_vulnerabilities_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerabilities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_scores" ADD CONSTRAINT "epss_scores_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_scores" ADD CONSTRAINT "epss_scores_cve_identifier_id_identifiers_id_fk" FOREIGN KEY ("cve_identifier_id") REFERENCES "public"."identifiers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "kev_entries" ADD CONSTRAINT "kev_entries_vulnerability_id_vulnerabilities_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerabilities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "kev_entries" ADD CONSTRAINT "kev_entries_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "kev_entries" ADD CONSTRAINT "kev_entries_cve_identifier_id_identifiers_id_fk" FOREIGN KEY ("cve_identifier_id") REFERENCES "public"."identifiers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD CONSTRAINT "severity_metrics_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "severity_metrics" ADD CONSTRAINT "severity_metrics_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssvc_assessments" ADD CONSTRAINT "ssvc_assessments_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssvc_assessments" ADD CONSTRAINT "ssvc_assessments_source_record_id_source_records_id_fk" FOREIGN KEY ("source_record_id") REFERENCES "public"."source_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_weaknesses" ADD CONSTRAINT "vulnerability_record_weaknesses_vulnerability_record_id_vulnerability_records_id_fk" FOREIGN KEY ("vulnerability_record_id") REFERENCES "public"."vulnerability_records"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_record_weaknesses" ADD CONSTRAINT "vulnerability_record_weaknesses_weakness_id_weaknesses_id_fk" FOREIGN KEY ("weakness_id") REFERENCES "public"."weaknesses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "cvss_metric_details_metric_idx" ON "cvss_metric_details" USING btree ("severity_metric_id");--> statement-breakpoint
CREATE INDEX "cvss_metric_details_attack_vector_idx" ON "cvss_metric_details" USING btree ("attack_vector");--> statement-breakpoint
CREATE UNIQUE INDEX "epss_scores_cve_date_idx" ON "epss_scores" USING btree ("cve_identifier_id","score_date");--> statement-breakpoint
CREATE INDEX "epss_scores_source_record_idx" ON "epss_scores" USING btree ("source_record_id");--> statement-breakpoint
CREATE INDEX "epss_scores_vulnerability_idx" ON "epss_scores" USING btree ("vulnerability_id");--> statement-breakpoint
CREATE UNIQUE INDEX "kev_entries_source_record_idx" ON "kev_entries" USING btree ("source_record_id");--> statement-breakpoint
CREATE INDEX "kev_entries_cve_idx" ON "kev_entries" USING btree ("cve_identifier_id");--> statement-breakpoint
CREATE INDEX "kev_entries_vulnerability_idx" ON "kev_entries" USING btree ("vulnerability_id");--> statement-breakpoint
CREATE INDEX "severity_metrics_record_idx" ON "severity_metrics" USING btree ("vulnerability_record_id");--> statement-breakpoint
CREATE INDEX "severity_metrics_source_record_idx" ON "severity_metrics" USING btree ("source_record_id");--> statement-breakpoint
CREATE INDEX "severity_metrics_system_idx" ON "severity_metrics" USING btree ("system");--> statement-breakpoint
CREATE INDEX "ssvc_assessments_record_idx" ON "ssvc_assessments" USING btree ("vulnerability_record_id");--> statement-breakpoint
CREATE INDEX "ssvc_assessments_source_record_idx" ON "ssvc_assessments" USING btree ("source_record_id");--> statement-breakpoint
CREATE INDEX "ssvc_assessments_exploitation_idx" ON "ssvc_assessments" USING btree ("exploitation");--> statement-breakpoint
CREATE INDEX "vulnerability_record_weaknesses_weakness_idx" ON "vulnerability_record_weaknesses" USING btree ("weakness_id");--> statement-breakpoint
CREATE UNIQUE INDEX "weaknesses_cwe_id_idx" ON "weaknesses" USING btree ("cwe_id");--> statement-breakpoint
ALTER TABLE "version_ranges" ADD CONSTRAINT "version_ranges_affected_product_id_affected_products_id_fk" FOREIGN KEY ("affected_product_id") REFERENCES "public"."affected_products"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "version_ranges_affected_product_idx" ON "version_ranges" USING btree ("affected_product_id");--> statement-breakpoint
ALTER TABLE "version_ranges" ADD CONSTRAINT "version_ranges_one_affected_target_chk" CHECK (("version_ranges"."affected_package_id" is not null and "version_ranges"."affected_product_id" is null) or ("version_ranges"."affected_package_id" is null and "version_ranges"."affected_product_id" is not null));