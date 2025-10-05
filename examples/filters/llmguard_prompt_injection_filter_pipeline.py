"""
title: LLM Guard Filter Pipeline
author: jannikstdl
date: 2024-05-30
version: 1.0
license: MIT
description: A pipeline for filtering out potential prompt injections using the LLM Guard library.
requirements: llm-guard
"""

from typing import List, Optional
from schemas import OpenAIChatMessage
from pydantic import BaseModel
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType
import os

class Pipeline:
    def __init__(self):
        # Pipeline filters are only compatible with Open WebUI
        # You can think of filter pipeline as a middleware that can be used to edit the form data before it is sent to the OpenAI API.
        self.type = "filter"

        # Optionally, you can set the id and name of the pipeline.
        # Assign a unique identifier to the pipeline.
        # The identifier must be unique across all pipelines.
        # The identifier must be an alphanumeric string that can include underscores or hyphens. It cannot contain spaces, special characters, slashes, or backslashes.
        self.id = "llmguard_prompt_injection_filter_pipeline"
        self.name = "LLMGuard Prompt Injection Filter"

        class Valves(BaseModel):
            # List target pipeline ids (models) that this filter will be connected to.
            # If you want to connect this filter to all pipelines, you can set pipelines to ["*"]
            # e.g. ["llama3:latest", "gpt-3.5-turbo"]
            pipelines: List[str] = []

            # Assign a priority level to the filter pipeline.
            # The priority level determines the order in which the filter pipelines are executed.
            # The lower the number, the higher the priority.
            priority: int = 0

        # Initialize
        self.valves = Valves(
            **{
                "pipelines": ["*"],  # Connect to all pipelines
            }
        )

        self.model = None

        pass

    async def on_startup(self):
        # This function is called when the server is started.
        print(f"on_startup:{__name__}")

        self.model = PromptInjection(model="protectai/gpt-pi-detector-light", threshold=0.8, match_type=MatchType.FULL)
        pass

    async def on_shutdown(self):
        # This function is called when the server is stopped.
        print(f"on_shutdown:{__name__}")
        pass

    async def on_valves_updated(self):
        # This function is called when the valves are updated.
        pass

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        print(f"inlet:{__name__}")

        user_message = body["messages"][-1]["content"]

        # Normalizza il contenuto in stringa (supporta multimodale)
        if isinstance(user_message, list):
            parts = []
            for item in user_message:
                if isinstance(item, dict):
                    if "text" in item:
                        parts.append(item["text"])
                    elif "image_url" in item:
                        parts.append("[image]")
                    else:
                        parts.append(str(item))
                else:
                    parts.append(str(item))
            user_message = " ".join(parts)

        elif not isinstance(user_message, str):
            user_message = str(user_message)

        sanitized_prompt, is_valid, risk_score = self.model.scan(user_message)

        if risk_score > 0.8:
            raise Exception("Prompt injection detected")

        return body
