"""
WebSocket endpoint for real-time dashboard updates.

Provides live streaming of:
- Compliance assessment results
- Alert notifications
- System status changes
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Set, Dict, Any
from weakref import WeakSet

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from pydantic import BaseModel

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        # Active connections by topic
        self.connections: Dict[str, Set[WebSocket]] = {
            "compliance": set(),
            "alerts": set(),
            "systems": set(),
            "all": set(),
        }
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, topics: list[str]):
        """Accept connection and add to topic subscriptions."""
        await websocket.accept()
        
        async with self._lock:
            for topic in topics:
                if topic in self.connections:
                    self.connections[topic].add(websocket)
            # Always add to "all"
            self.connections["all"].add(websocket)
    
    async def disconnect(self, websocket: WebSocket):
        """Remove connection from all topics."""
        async with self._lock:
            for topic_connections in self.connections.values():
                topic_connections.discard(websocket)
    
    async def broadcast(self, topic: str, message: dict):
        """Broadcast message to all connections subscribed to topic."""
        async with self._lock:
            connections = self.connections.get(topic, set()).copy()
        
        # Add timestamp if not present
        if "timestamp" not in message:
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        message["topic"] = topic
        message_json = json.dumps(message)
        
        disconnected = []
        for connection in connections:
            try:
                await connection.send_text(message_json)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    for topic_connections in self.connections.values():
                        topic_connections.discard(conn)
    
    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to a specific connection."""
        message_json = json.dumps(message)
        await websocket.send_text(message_json)
    
    def get_connection_count(self) -> Dict[str, int]:
        """Get count of connections per topic."""
        return {topic: len(conns) for topic, conns in self.connections.items()}


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    topics: str = Query("all", description="Comma-separated topics: compliance,alerts,systems,all"),
):
    """
    WebSocket endpoint for real-time updates.
    
    Connect and subscribe to topics:
    - `compliance`: Compliance assessment results
    - `alerts`: Alert notifications  
    - `systems`: System status changes
    - `all`: All updates
    
    Messages are JSON with format:
    ```json
    {
        "type": "assessment_result" | "alert" | "system_update" | "heartbeat",
        "topic": "compliance" | "alerts" | "systems",
        "data": { ... },
        "timestamp": "2024-01-01T00:00:00Z"
    }
    ```
    """
    topic_list = [t.strip() for t in topics.split(",") if t.strip()]
    
    await manager.connect(websocket, topic_list)
    
    # Send welcome message
    await manager.send_personal(websocket, {
        "type": "connected",
        "topics": topic_list,
        "message": "Connected to PACT real-time updates",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    
    try:
        while True:
            # Wait for messages from client (ping/pong or commands)
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0  # 30 second timeout for heartbeat
                )
                
                # Handle client messages
                try:
                    message = json.loads(data)
                    msg_type = message.get("type")
                    
                    if msg_type == "ping":
                        await manager.send_personal(websocket, {
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                    
                    elif msg_type == "subscribe":
                        new_topics = message.get("topics", [])
                        async with manager._lock:
                            for topic in new_topics:
                                if topic in manager.connections:
                                    manager.connections[topic].add(websocket)
                        await manager.send_personal(websocket, {
                            "type": "subscribed",
                            "topics": new_topics,
                        })
                    
                    elif msg_type == "unsubscribe":
                        old_topics = message.get("topics", [])
                        async with manager._lock:
                            for topic in old_topics:
                                if topic in manager.connections:
                                    manager.connections[topic].discard(websocket)
                        await manager.send_personal(websocket, {
                            "type": "unsubscribed",
                            "topics": old_topics,
                        })
                    
                except json.JSONDecodeError:
                    pass  # Ignore malformed messages
                    
            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_personal(websocket, {
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@router.get("/ws/stats")
async def websocket_stats():
    """Get WebSocket connection statistics."""
    return {
        "connections": manager.get_connection_count(),
        "topics_available": list(manager.connections.keys()),
    }


# Helper functions for broadcasting from other parts of the app

async def broadcast_compliance_update(data: dict):
    """Broadcast a compliance update to connected clients."""
    await manager.broadcast("compliance", {
        "type": "assessment_result",
        "data": data,
    })


async def broadcast_alert(data: dict):
    """Broadcast an alert to connected clients."""
    await manager.broadcast("alerts", {
        "type": "alert",
        "data": data,
    })


async def broadcast_system_update(data: dict):
    """Broadcast a system status update to connected clients."""
    await manager.broadcast("systems", {
        "type": "system_update",
        "data": data,
    })

