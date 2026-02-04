import asyncio
import argparse
import os
import logging
from websockets.asyncio.client import connect
import json
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
        
async def run_flow(id: str, probe: str, llm: str, ws_url: str):
    async with httpx.AsyncClient() as client:
        headers = {'content-type': 'application/json'}
        data = {
            "id": id,
            "probe": probe}
                
        run_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/run", json=data, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        if run_resp.status_code == 200:
            run_data = await run_resp.json()

            async with connect(uri=ws_url) as websocket:
                umj_result_data = {
                    'flow_run_result': run_data,
                    'llm': llm,
                    'act': "prb_task_rslt"
                    }
                
                await websocket.send(json.dumps(umj_result_data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate network monitoring tasks.")
    parser.add_argument(
        '-id', '--flow_id', 
        type=str, 
        help="ID of the flow to run"
    )
    parser.add_argument(
        '-p', '--probe', 
        type=str, 
        help="Probe flow is assigned to"
    )
    parser.add_argument(
        '-llm', '--llm_analysis', 
        type=str, 
        help="Whether to perform LLM analysis on the flow results (true/false)"
    )
    parser.add_argument(
        '-ws', '--ws_url', 
        type=str, 
        help="WebSocket URL for sending results back to the monitoring system"
    )
    args = parser.parse_args()

    asyncio.run(run_flow(id=args.flow_id, probe=args.probe, llm=args.llm_analysis, ws_url=args.ws_url))