variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = "5c6145d4-cca6-4da7-ad6c-83db5c8698df"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "project_name" {
  description = "Project name used in resource naming"
  type        = string
  default     = "aisentinel"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "openai_api_key" {
  description = "OpenAI API key for vulnerability prioritization"
  type        = string
  sensitive   = true
}

variable "container_image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "container_cpu" {
  description = "CPU cores for the container"
  type        = number
  default     = 1.0
}

variable "container_memory" {
  description = "Memory for the container (e.g. 2Gi)"
  type        = string
  default     = "2Gi"
}

variable "max_replicas" {
  description = "Maximum number of container replicas"
  type        = number
  default     = 3
}

variable "min_replicas" {
  description = "Minimum number of container replicas"
  type        = number
  default     = 0
}
