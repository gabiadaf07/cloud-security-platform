resource "aws_ebs_volume" "encrypted" {
  availability_zone = "eu-central-1a"
  encrypted         = true
  kms_key_id        = aws_kms_key.secure.arn
}

resource "aws_kms_key" "secure" {
  enable_key_rotation = true
}

resource "aws_backup_vault" "secure" {
  name        = "secure"
  kms_key_arn = aws_kms_key.secure.arn
}

resource "aws_instance" "secure" {
  ami           = "ami-example"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}
