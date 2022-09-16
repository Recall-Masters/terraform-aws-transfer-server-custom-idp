# terraform-aws-transfer-server-custom-idp

This Terraform module will create a custom identity provider based on AWS Secrets (managed by AWS Secret Manager) for the AWS Transfer Familiy.

### Example usage
Create a SFTP server with the custom identity provider.

```hcl
module "transfer-server-custom-idp" {
  name_prefix = var.name_prefix
  source  = "Recall-Masters/transfer-server-custom-idp/aws"
  version = "1.0.4"

  region = var.region
  
  s3_bucket_name = "my-test-ftp-bucket"
  home_directory_template = "{{ secret.category }}/{{ user_name }}"
}
```

## Parameters

* `home_directory_template` is a Jinja2 template which is used to render the path (S3 prefix) to use under the `s3_bucket_name` specified. Variables supported:
  * `user_name` is the name of the user who has logged in;
  * `secret` is the contents of the Secret Manager configuration. **Be careful!** If you expose, say, `{{ secret.password }}` here it will mean a MAJOR security leak.
