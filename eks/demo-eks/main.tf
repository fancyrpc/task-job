provider "aws" {
  region = "eu-central-1"
}

terraform {
  backend "s3" {
    bucket         = "infra-demo-tf-state"
    region         = "eu-central-1"
    key            = "terraform.tfstate"
    dynamodb_table = "infra-demo-tf-lock"
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30.0"
    }
  }
}
