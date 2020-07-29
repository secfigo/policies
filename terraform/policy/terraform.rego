package main

#  Terragoat Compliance as Code checks with Rego

#Checking the variables to the terraform definition file

deny [msg]{
	some i
	availability_zone := input.variables.availability_zone[i]
    not contains(availability_zone, "eu")
    msg := sprintf("in the wrong availability zone: %v. System needs to be deployed in EU", [availability_zone])
}

deny [msg]{
	some i
	availability_zone2 := input.variables.availability_zone2[i]
    not contains(availability_zone2, "eu")
    msg := sprintf("in the wrong availability zone 2: %v. System needs to be deployed in EU", [availability_zone2])
}

deny [msg]{
	some i
	region := input.variables.region[i]
    not contains(region, "eu")
    msg := sprintf("in the wrong region: %v. System needs to be deployed in EU", [region])
}

deny [msg]{
	some i
	password := input.variables.password[i]
    not startswith(password, "$")
    msg := sprintf("you have hardcoded crendentials. hide the keys in the key vault. Password content: %v More info on how to do it in: http:://git/internal.local/using-secret-vault ", [password])
}

# Checks relating to configuration of the Terraform provider

deny [msg]{
	some i, j
	aws_keys := input.configuration.provider_config[i].expressions.access_key[j]
    not startswith(aws_keys, "$")
    msg := sprintf("The Terraform AWS provider config has cleartext access key. Key: %v Please use the key vault", [aws_keys])
}

