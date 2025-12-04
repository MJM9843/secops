# File: backend/app/api/services/aws_service.py

import boto3
import logging
from botocore.exceptions import ClientError
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AWSService:
    """Service class for AWS resource operations"""
    
    def __init__(self, role_arn: str):
        self.role_arn = role_arn
        self._credentials = None
        self._credentials_expiry = None
        logger.info(f"Initializing AWSService with role: {role_arn}")
        self._assume_role()
    
    def _assume_role(self):
        """Assume the IAM role and store credentials"""
        try:
            logger.info(f"Assuming role: {self.role_arn}")
            sts_client = boto3.client('sts')
            response = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName='SecOpsSession',
                DurationSeconds=3600
            )
            self._credentials = response['Credentials']
            self._credentials_expiry = response['Credentials']['Expiration']
            logger.info(f"Role assumed successfully. Credentials expire at: {self._credentials_expiry}")
        except ClientError as e:
            logger.error(f"Failed to assume role: {str(e)}")
            raise
    
    def _get_client(self, service_name: str, region: str):
        """Get boto3 client with assumed role credentials"""
        # Check if credentials are about to expire (less than 5 minutes left)
        if self._credentials_expiry:
            time_left = (self._credentials_expiry - datetime.now(self._credentials_expiry.tzinfo)).total_seconds()
            if time_left < 300:  # Less than 5 minutes
                logger.warning(f"Credentials expiring soon ({time_left}s left), re-assuming role")
                self._assume_role()
        
        return boto3.client(
            service_name,
            region_name=region,
            aws_access_key_id=self._credentials['AccessKeyId'],
            aws_secret_access_key=self._credentials['SecretAccessKey'],
            aws_session_token=self._credentials['SessionToken']
        )
    
    def get_ec2_instances(self, region: str) -> List[Dict]:
        """Get all EC2 instances in a region"""
        try:
            logger.info(f"Fetching EC2 instances in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_instances()
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launch_time': instance['LaunchTime'].isoformat(),
                        'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                        'public_ip': instance.get('PublicIpAddress', 'N/A'),
                        'has_iam_role': bool(instance.get('IamInstanceProfile')),
                        'region': region
                    })
            
            logger.info(f"Found {len(instances)} EC2 instances in {region}")
            return instances
        except Exception as e:
            logger.error(f"Error fetching EC2 instances in {region}: {str(e)}")
            return []
    
    def get_s3_buckets(self) -> List[Dict]:
        """Get all S3 buckets (global service)"""
        try:
            logger.info("Fetching S3 buckets")
            s3 = self._get_client('s3', 'us-east-1')
            response = s3.list_buckets()
            
            buckets = []
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Get bucket region
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location['LocationConstraint'] or 'us-east-1'
                except:
                    region = 'unknown'
                
                buckets.append({
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'region': region
                })
            
            logger.info(f"Found {len(buckets)} S3 buckets")
            return buckets
        except Exception as e:
            logger.error(f"Error fetching S3 buckets: {str(e)}")
            return []
    
    def get_ebs_snapshots(self, region: str) -> List[Dict]:
        """Get all EBS snapshots in a region"""
        try:
            logger.info(f"Fetching EBS snapshots in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_snapshots(OwnerIds=['self'])
            
            snapshots = []
            for snapshot in response['Snapshots']:
                snapshots.append({
                    'id': snapshot['SnapshotId'],
                    'volume_id': snapshot['VolumeId'],
                    'state': snapshot['State'],
                    'start_time': snapshot['StartTime'].isoformat(),
                    'encrypted': snapshot['Encrypted'],
                    'size': snapshot['VolumeSize'],
                    'region': region
                })
            
            logger.info(f"Found {len(snapshots)} snapshots in {region}")
            return snapshots
        except Exception as e:
            logger.error(f"Error fetching snapshots in {region}: {str(e)}")
            return []
    
    def get_security_groups(self, region: str) -> List[Dict]:
        """Get all security groups in a region"""
        try:
            logger.info(f"Fetching security groups in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_security_groups()
            
            security_groups = []
            for sg in response['SecurityGroups']:
                security_groups.append({
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg.get('VpcId', 'N/A'),
                    'ingress_rules': len(sg.get('IpPermissions', [])),
                    'egress_rules': len(sg.get('IpPermissionsEgress', [])),
                    'region': region
                })
            
            logger.info(f"Found {len(security_groups)} security groups in {region}")
            return security_groups
        except Exception as e:
            logger.error(f"Error fetching security groups in {region}: {str(e)}")
            return []
    
    def get_vpcs(self, region: str) -> List[Dict]:
        """Get all VPCs in a region"""
        try:
            logger.info(f"Fetching VPCs in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_vpcs()
            
            vpcs = []
            for vpc in response['Vpcs']:
                name = 'N/A'
                for tag in vpc.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                vpcs.append({
                    'id': vpc['VpcId'],
                    'name': name,
                    'cidr_block': vpc['CidrBlock'],
                    'is_default': vpc['IsDefault'],
                    'state': vpc['State'],
                    'region': region
                })
            
            logger.info(f"Found {len(vpcs)} VPCs in {region}")
            return vpcs
        except Exception as e:
            logger.error(f"Error fetching VPCs in {region}: {str(e)}")
            return []
    
    def get_iam_roles(self) -> List[Dict]:
        """Get all IAM roles (global service)"""
        try:
            logger.info("Fetching IAM roles")
            iam = self._get_client('iam', 'us-east-1')
            response = iam.list_roles()
            
            roles = []
            for role in response['Roles']:
                roles.append({
                    'name': role['RoleName'],
                    'arn': role['Arn'],
                    'created': role['CreateDate'].isoformat(),
                    'path': role['Path']
                })
            
            logger.info(f"Found {len(roles)} IAM roles")
            return roles
        except Exception as e:
            logger.error(f"Error fetching IAM roles: {str(e)}")
            return []
    
    def get_iam_policies(self) -> List[Dict]:
        """Get all IAM policies (global service)"""
        try:
            logger.info("Fetching IAM policies")
            iam = self._get_client('iam', 'us-east-1')
            response = iam.list_policies(Scope='Local')
            
            policies = []
            for policy in response['Policies']:
                policies.append({
                    'name': policy['PolicyName'],
                    'arn': policy['Arn'],
                    'created': policy['CreateDate'].isoformat(),
                    'attachment_count': policy['AttachmentCount']
                })
            
            logger.info(f"Found {len(policies)} IAM policies")
            return policies
        except Exception as e:
            logger.error(f"Error fetching IAM policies: {str(e)}")
            return []
    
    def get_rds_instances(self, region: str) -> List[Dict]:
        """Get all RDS instances in a region"""
        try:
            logger.info(f"Fetching RDS instances in {region}")
            rds = self._get_client('rds', region)
            response = rds.describe_db_instances()
            
            instances = []
            for db in response['DBInstances']:
                instances.append({
                    'id': db['DBInstanceIdentifier'],
                    'engine': db['Engine'],
                    'engine_version': db['EngineVersion'],
                    'instance_class': db['DBInstanceClass'],
                    'status': db['DBInstanceStatus'],
                    'encrypted': db.get('StorageEncrypted', False),
                    'public_access': db.get('PubliclyAccessible', False),
                    'deletion_protection': db.get('DeletionProtection', False),
                    'region': region
                })
            
            logger.info(f"Found {len(instances)} RDS instances in {region}")
            return instances
        except Exception as e:
            logger.error(f"Error fetching RDS instances in {region}: {str(e)}")
            return []
    
    def get_ami_images(self, region: str) -> List[Dict]:
        """Get all AMI images owned by account in a region"""
        try:
            logger.info(f"Fetching AMI images in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_images(Owners=['self'])
            
            images = []
            for image in response['Images']:
                images.append({
                    'id': image['ImageId'],
                    'name': image.get('Name', 'N/A'),
                    'state': image['State'],
                    'public': image['Public'],
                    'creation_date': image.get('CreationDate', 'N/A'),
                    'region': region
                })
            
            logger.info(f"Found {len(images)} AMI images in {region}")
            return images
        except Exception as e:
            logger.error(f"Error fetching AMI images in {region}: {str(e)}")
            return []
    
    def get_ebs_volumes(self, region: str) -> List[Dict]:
        """Get all EBS volumes in a region"""
        try:
            logger.info(f"Fetching EBS volumes in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_volumes()
            
            volumes = []
            for volume in response['Volumes']:
                attachments = volume.get('Attachments', [])
                is_attached = len(attachments) > 0
                
                volumes.append({
                    'id': volume['VolumeId'],
                    'size': volume['Size'],
                    'type': volume['VolumeType'],
                    'state': volume['State'],
                    'encrypted': volume['Encrypted'],
                    'attached': is_attached,
                    'instance_id': attachments[0]['InstanceId'] if is_attached else 'N/A',
                    'region': region
                })
            
            logger.info(f"Found {len(volumes)} EBS volumes in {region}")
            return volumes
        except Exception as e:
            logger.error(f"Error fetching EBS volumes in {region}: {str(e)}")
            return []
    
    def get_elastic_ips(self, region: str) -> List[Dict]:
        """Get all Elastic IPs in a region"""
        try:
            logger.info(f"Fetching Elastic IPs in {region}")
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_addresses()
            
            eips = []
            for address in response['Addresses']:
                eips.append({
                    'public_ip': address.get('PublicIp', 'N/A'),
                    'allocation_id': address.get('AllocationId', 'N/A'),
                    'associated': 'InstanceId' in address or 'NetworkInterfaceId' in address,
                    'instance_id': address.get('InstanceId', 'N/A'),
                    'region': region
                })
            
            logger.info(f"Found {len(eips)} Elastic IPs in {region}")
            return eips
        except Exception as e:
            logger.error(f"Error fetching Elastic IPs in {region}: {str(e)}")
            return []
    
    def get_lambda_functions(self, region: str) -> List[Dict]:
        """Get all Lambda functions in a region"""
        try:
            logger.info(f"Fetching Lambda functions in {region}")
            lambda_client = self._get_client('lambda', region)
            response = lambda_client.list_functions()
            
            functions = []
            for func in response['Functions']:
                functions.append({
                    'name': func['FunctionName'],
                    'runtime': func['Runtime'],
                    'handler': func['Handler'],
                    'code_size': func['CodeSize'],
                    'last_modified': func['LastModified'],
                    'memory': func['MemorySize'],
                    'region': region
                })
            
            logger.info(f"Found {len(functions)} Lambda functions in {region}")
            return functions
        except Exception as e:
            logger.error(f"Error fetching Lambda functions in {region}: {str(e)}")
            return []
    
    def get_cloudtrail_trails(self, region: str) -> List[Dict]:
        """Get all CloudTrail trails in a region"""
        try:
            logger.info(f"Fetching CloudTrail trails in {region}")
            cloudtrail = self._get_client('cloudtrail', region)
            response = cloudtrail.describe_trails()
            
            trails = []
            for trail in response['trailList']:
                status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                
                trails.append({
                    'name': trail['Name'],
                    'arn': trail['TrailARN'],
                    'is_logging': status['IsLogging'],
                    'is_multi_region': trail.get('IsMultiRegionTrail', False),
                    's3_bucket': trail['S3BucketName'],
                    'region': region
                })
            
            logger.info(f"Found {len(trails)} CloudTrail trails in {region}")
            return trails
        except Exception as e:
            logger.error(f"Error fetching CloudTrail trails in {region}: {str(e)}")
            return []
