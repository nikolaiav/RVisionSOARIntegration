import json
import logging
import os

import yaml
import uvicorn
from fastapi import FastAPI

from app.helpers import setup_logging
from app.services import RVisionSOARIntegration

with open('./conf/config.yml', 'r') as f:
    config = yaml.safe_load(f)
setup_logging('./conf/logging.yml')


app = FastAPI()
log = logging.getLogger('Common')
integration = RVisionSOARIntegration(config)


@app.get("/ioc")
async def get_ioc(identifier: str):
    if identifier is None or identifier.strip() == '':
        log.error('Empty identifier parameter')
        return 404
    integration.send_enriched_iocs(identifier)
    return 'OK'

log.info('Run Service on {}:{}'.format(os.getenv('APPHOST'), os.getenv('APPPORT')))

if __name__ == "__main__":
    uvicorn.run(app, host=os.getenv('APPHOST'), port=int(os.getenv('APPPORT')))
