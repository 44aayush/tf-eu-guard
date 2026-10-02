resource "aws_lb" "web" {
  name               = "${local.resource_prefix.value}-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web-node.id]
  subnets            = [aws_subnet.web_subnet.id]

  enable_deletion_protection = false # CKV_AWS_150: deletion protection disabled
  drop_invalid_header_fields = false # CKV_AWS_131: invalid HTTP headers are forwarded, not dropped
  desync_mitigation_mode     = "monitor" # CKV_AWS_328: should be "defensive" or "strictest"

  # CKV_AWS_91: no access_logs block — no ELBv2 access logging configured.
}

resource "aws_lb_target_group" "web" {
  name     = "${local.resource_prefix.value}-web-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.web_vpc.id

  # CKV_AWS_261: no health_check block defined for the target group.
}

resource "aws_lb_listener" "web_http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP" # CKV_AWS_2: listener protocol is HTTP, not HTTPS

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
