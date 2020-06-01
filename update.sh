#!/bin/bash

aws s3 cp FractalService/FractalService/bin/Debug/FractalService.exe s3://fractal-cloud-setup-s3bucket/FractalService.exe && \
curl -X POST --data-urlencode "payload={\"channel\": \"#general\", \"username\": \"fractal-bot\", \"text\": \"FractalService.exe updated in AWS S3\", \"icon_emoji\": \":ghost:\"}" https://hooks.slack.com/services/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
