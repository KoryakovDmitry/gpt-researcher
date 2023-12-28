import hashlib
import json
import logging
import os

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from gpt_researcher import GPTResearcher

from redis import Redis
from dotenv import load_dotenv

load_dotenv()

# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis configuration
CACHE_EXPIRATION = os.getenv("CACHE_EXPIRATION", 3600)
DB = 2
REDIS_HOST = os.getenv("CACHE_HOST", "cache")

REDIS_PORT = os.getenv("CACHE_PORT", 6379)
logger.info(f"{REDIS_HOST}, {REDIS_PORT}")

redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=DB)


def hash_string(
    input_string,
    algorithm="md5",
):
    """
    Hashes an input string using the specified algorithm.

    :param input_string: The string to be hashed.
    :param algorithm: The hashing algorithm to use (default is 'sha256').
    :return: The hexadecimal hash of the input string.
    """
    # Create a new hash object using the specified algorithm
    hash_object = hashlib.new(algorithm)

    # Update the hash object with the bytes of the input string
    hash_object.update(input_string.encode())

    # Return the hexadecimal representation of the hash
    return hash_object.hexdigest()


def cache_data(cache_name, data):
    redis_client.set(cache_name, json.dumps(data), ex=CACHE_EXPIRATION)


def get_cached_data(cache_name):
    cached_data = redis_client.get(cache_name)
    return json.loads(cached_data) if cached_data else None


app = FastAPI()


class ReportRequest(BaseModel):
    query: str
    report_type: str = "research_report"


@app.post("/generate_report")
async def generate_report(
    request: ReportRequest,
    no_cache: bool = False,
):
    """
    Endpoint to generate a research report based on the given query.
    """
    query = request.query
    report_type = request.report_type
    search_key = hash_string(f"data_{query}_{report_type}")

    if not no_cache:
        cached = get_cached_data(search_key)
        if cached:
            logger.info("Found result in cache: %s", search_key)
            return cached

    # Initialize the GPT Researcher
    researcher = GPTResearcher(query=query, report_type=report_type, config_path=None)

    # Run Research and get the report
    report = await researcher.run()

    if not no_cache:
        cache_data(search_key, {"data": report})
        logger.info("Cached result data: %s", search_key)

    return {"data": report}
