"""constants used by """
from configparser import ConfigParser
from pathlib import Path

HERE = Path(__file__).parent

# consumer ID and consumer secret are stored in a config.ini file
CONSUMER_INI = HERE.joinpath('consumer.ini')
CONFIG = ConfigParser()
CONFIG.read(CONSUMER_INI)

# FigShare uses the term 'consumer' ID and secret, instead of 'client'
CONSUMER_ID = CONFIG['CONSUMER']['ID']
CONSUMER_SECRET = CONFIG['CONSUMER']['SECRET']
REDIRECT_URI = CONFIG['CONSUMER']['REDIRECT_URI']
PORT = int(CONFIG['CONSUMER']['PORT'])

FIGSHARE_AUTHORIZATION_ENDPOINT = 'https://figshare.com/account/applications/authorize'
FIGSHARE_TOKEN_ENDPOINT = 'https://api.figshare.com/v2/token'
