resource "aws_s3_bucket" "encrypted_but_publicly_unprotected" {
  bucket = "plan-regression-fixture"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fixture" {
  bucket = aws_s3_bucket.encrypted_but_publicly_unprotected.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
