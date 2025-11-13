
**YouTube MCP Server**

A MCP server for integrating and automating workflows with the YouTube Data API. This server provides OAuth2 authentication, programmable tool endpoints for channel/video/comment management, and full YouTube API access with persistent local token storage.

**Features**

OAuth2 Authentication: Secure connection to YouTube account using Google OAuth2; persistent token storage

Account Status: Check connection and get account/channel info

Video Search & Details: Search, retrieve, and analyze YouTube videos with advanced filters

Channel Operations: List channels, view channel details, list channel or user videos, get analytics

Playlist Management: Get playlists or playlist videos by channel/user

Comment Access: Read top comments on videos and list message threads

Trending Videos: Get top trending videos by region and category

Read/Write Access: Tools ready for full integration of YouTube Data API v3 operations (authenticated)

Local Token Management: Tokens stored secure in user's home directory for persistent connection

Extensible Tool API: All endpoints available via ModelContextProtocol tool handlers


**Tool Endpoints**

The MCP server exposes structured YouTube operations for LLM/tools:

**Authentication & Status**

youtube_authenticate: Starts OAuth consent flow or completes with given auth code

youtube_status: Checks connection status and authenticated channel

**Video Operations**

youtube_search_videos: Search YouTube videos by query, filters (date, duration, order, etc.)

youtube_get_video: Get details for a specific video (+optional comments)

youtube_get_my_channel: Authenticated user's channel info (+optional analytics)

youtube_list_my_videos: List videos for authenticated user

youtube_list_channel_videos: List videos from any channel

**Channel Operations**

youtube_get_channel: Get public channel info by channel ID or username

**Playlist Operations**

youtube_get_playlists: Get playlists by channel/user

youtube_get_playlist_videos: Get video list for a playlist

**Comments**

youtube_get_comments: Get video comments (max 100 per call)

**Trending**

youtube_get_trending: List trending videos for a country/region and category
