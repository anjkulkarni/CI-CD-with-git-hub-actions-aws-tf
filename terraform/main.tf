terraform {
    required_providers {
      aws ={
          source = "hashicorp/aws"
          version = "~>4.0"
      }
    }
    backend "s3" {
        key = "aws/ec2-deploy/terraform.tfstate"
      
    }
}

provider "aws" {
    region = var.region
  
}

resource "aws_instance" "ec2-deployer" {
    ami = "ami-03f65b8614a860c29"
    instance_type = "t2.micro"
    subnet_id = var.subnet-id
    key_name = aws_key_pair.Deployer.key_name
    vpc_security_group_ids = [aws_security_group.maingroup.id]
    iam_instance_profile = aws_iam_instance_profile.ec2-profile.name
    

    connection {
      type = "ssh"
      host = self.public_ip
      user = "ubuntu"
      private_key = var.parivate_key
      timeout = "4m"
    }
    tags = {
      "name" = "DeployVm" 
    }
}

resource "aws_iam_role" "ecr-auth" {
    name =  "ec2-ecr-auth"
    assume_role_policy = jsonencode({

    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com"
                ]
            }
        }
    ]

  })
    inline_policy {
        name = "ecr-read-only"
        policy = jsonencode({
        
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:GetLifecyclePolicy",
                "ecr:GetLifecyclePolicyPreview",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        }
    ]
}
    )
  }   
    }
  

resource "aws_iam_instance_profile" "ec2-profile" {
    name = "ec2-profile"
    role = aws_iam_role.ecr-auth.name
  
}

resource "aws_key_pair" "Deployer" {
    key_name = var.key_name
    public_key = var.public_key
  
}

resource "aws_security_group" "maingroup" {
    name = "ec2-sg"
    vpc_id = var.vpc_id
    egress = [{
        cidr_blocks = ["0.0.0.0/0"]
        description = ""
        ipv6_cidr_blocks = []
        prefix_list_ids = []
        security_groups = []
        protocol = "-1"
        from_port = 0
        to_port = 0
        self = false

    }]
    ingress = [
        {cidr_blocks = ["0.0.0.0/0"]
        description = ""
        ipv6_cidr_blocks = []
        prefix_list_ids = []
        security_groups = []
        protocol = "tcp"
        from_port = 22
        to_port = 22
        self = false},

        {cidr_blocks = ["0.0.0.0/0"]
        description = ""
        ipv6_cidr_blocks = []
        prefix_list_ids = []
        security_groups = []
        protocol = "tcp"
        from_port = 80
        to_port = 80
        self = false}
    ]
     
  
}

output "instance_public_ip" {
    value = aws_instance.ec2-deployer.public_ip
    sensitive = true
  
}