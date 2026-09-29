"use client";
import { useEffect, useRef, useCallback } from "react";
import { WS_FEED } from "./api";

export type FeedChannel = "events" | "alerts" | "status";

export interface FeedMessage {
  channel: FeedChannel;
  data: unknown;
}

type Handler = (msg: FeedMessage) => void;

export function useWebSocket(onMessage: Handler, channels: FeedChannel[] = ["events", "alerts", "status"]) {
  const wsRef = useRef<WebSocket | null>(null);
  const handleRef = useRef<Handler>(onMessage);
  handleRef.current = onMessage;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_FEED);
    wsRef.current = ws;

    ws.onopen = () => {
      // Subscribe to requested channels
      channels.forEach((ch) => ws.send(JSON.stringify({ action: "subscribe", channel: ch })));
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data as string) as FeedMessage;
        handleRef.current(msg);
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      // Auto-reconnect after 3s
      setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [channels]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);
}
