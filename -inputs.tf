variable "region" {
  description = "AWS Region"
  type        = string
}

variable secrets_prefix {
  description = "Prefix used to create AWS Secrets"
  default     = "SFTP"
  type        = string
}

variable "input_tags" {
  description = "Map of tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "name_prefix" {
  description = "String to use as prefix on object names"
  type        = string
}

variable name_suffix {
  description = "String to append to object names. This is optional, so start with dash if using"
  type        = string
  default     = ""
}


variable s3_bucket_name {
  description = "Name of the S3 bucket to connect SFTP server to."
}

variable sentry_dsn {
  description = "Provide a Sentry DSN to log errors and messages to Sentry."
  default = ""
  type = string
}

variable environment {
  description = "Environment (for example, dev, staging, or production). Used in Sentry logging."
  default = ""
  type = string
}

variable home_directory_template {
  description = "Jinja2 template to generate home directory path for a given user. For example: {{ secret.user_type }}/{{ user_name }}"
  type = string
}
