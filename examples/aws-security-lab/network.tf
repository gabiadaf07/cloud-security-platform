locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.lab.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-public-${count.index + 1}", Tier = "public" }
}

resource "aws_subnet" "application" {
  count = 2

  vpc_id                  = aws_vpc.lab.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 10 + count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-application-${count.index + 1}", Tier = "private-application" }
}

resource "aws_subnet" "database" {
  count = 2

  vpc_id                  = aws_vpc.lab.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 20 + count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-database-${count.index + 1}", Tier = "isolated-database" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table" "application" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.name}-private-application" }
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.name}-isolated-database" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "application" {
  count          = 2
  subnet_id      = aws_subnet.application[count.index].id
  route_table_id = aws_route_table.application.id
}

resource "aws_route_table_association" "database" {
  count          = 2
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

resource "aws_security_group" "application" {
  name        = "${var.name}-application"
  description = "Application tier; no direct internet ingress"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_security_group" "database" {
  name        = "${var.name}-database"
  description = "PostgreSQL only from the application tier"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "database_from_application" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.application.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "application_to_database" {
  security_group_id            = aws_security_group.application.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints"
  description = "TLS from application tier to interface endpoints"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_application" {
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.application.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "application_to_endpoints" {
  security_group_id            = aws_security_group.application.id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.lab.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.application[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.lab.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.application[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
}
