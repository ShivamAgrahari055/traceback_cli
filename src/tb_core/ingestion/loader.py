import os
from typing import List
from tb_core.core.models import Event
from .text_parser import TextParser

class LogLoader:
    def __init__(self):
        self.parser = TextParser()

    def load_file(self, filepath: str) -> List[Event]:
        print(f"Loading logs from: {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        events = []
        for line in lines:
            event = self.parser.parse_line(line)
            if event:
                events.append(event)
        return events

    def load_directory(self, directory_path: str) -> List[Event]:
        all_events = []
        for file in os.listdir(directory_path):
            if file.endswith(('.log', '.txt')):
                all_events.extend(self.load_file(os.path.join(directory_path, file)))
        return all_events
