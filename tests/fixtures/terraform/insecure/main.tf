resource "aws_security_group_rule" "world" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "public" {
  publicly_accessible     = true
  storage_encrypted       = false
  deletion_protection     = false
  backup_retention_period = 0
  password                = "NotARealPassword123"
}

resource "aws_ebs_volume" "plain" {
  availability_zone = "eu-central-1a"
  encrypted         = false
}

resource "aws_s3_bucket" "public" {
  bucket = "insecure-fixture"
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_kms_key" "no_rotation" {
  enable_key_rotation = false
}

resource "aws_cloudtrail" "weak" {
  name                       = "weak"
  s3_bucket_name             = "logs"
  is_multi_region_trail      = false
  enable_log_file_validation = false
}

resource "aws_iam_role_policy" "admin" {
  role   = "fixture"
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
POLICY
}

resource "aws_instance" "legacy_metadata" {
  ami           = "ami-example"
  instance_type = "t3.micro"
}

resource "aws_eks_cluster" "public" {
  name = "public"
  vpc_config {
    endpoint_public_access  = true
    endpoint_private_access = false
  }
}

resource "aws_backup_vault" "default_key" {
  name = "default-key"
}
