# hass-ubox — UBox Camera Home Assistant Add-on

Live stream from UBox (Ubia) cameras into Home Assistant, fully local and
on-demand: the camera session starts only while someone is watching and
stops `idle_timeout` seconds after the last viewer leaves (the last frame is
kept as the snapshot).

Fork of [wocaca/hass-ubox](https://github.com/wocaca/hass-ubox), translated
to English and reworked for a stable, smooth stream (see
[Changes in 0.8.0](#changes-in-080)).

## Install

1. Home Assistant → Settings → Add-ons → Add-on Store → ⋮ → Repositories, add:
   `https://github.com/robin994/hass-ubox`
2. Install **UBox Camera**. The add-on is built locally on first install
   (a few minutes).
3. Start it and open `http://<hass-ip>:8089/`. Log in with your **UBox app
   account** (cloud account, pick the right region). The camera uid and
   password are fetched from the cloud automatically and stored only in the
   add-on's `/data`.
4. Open the **Live** tab to check the picture.

`host_network` is on by default (needed for UDP hole punching).

## Home Assistant camera

Settings → Devices & services → Add integration → **MJPEG IP Camera**:

- MJPEG URL: `http://<hass-ip>:8089/video.mjpg`
- Still image URL: `http://<hass-ip>:8089/snap.jpg`

or in `configuration.yaml`:

```yaml
camera:
  - platform: mjpeg
    name: UBox Garden
    mjpeg_url: http://<hass-ip>:8089/video.mjpg
    still_image_url: http://<hass-ip>:8089/snap.jpg
```

If you set `http_password`, append `?key=<http_password>` to both URLs.

The thumbnail uses `snap.jpg` (cached frame, does not wake the camera);
opening the card connects to `video.mjpg` and starts the stream.

## Options (add-on Configuration tab)

| Option | Default | Meaning |
| --- | --- | --- |
| `stream` | `1` | `1` = main stream (high resolution), `0` = sub stream (low resolution, far lighter on CPU) |
| `fps` | `0` | `0` = every camera frame is passed through. `1`–`30` caps the frame rate |
| `jpeg_quality` | `5` | `2` (best) – `31` (worst) |
| `max_width` | `0` | `0` = original size; e.g. `1280` to downscale (recommended on Raspberry Pi) |
| `idle_timeout` | `60` | seconds without viewers before the camera session is stopped |
| `stall_timeout` | `20` | restart the session when no frame arrives for this long |
| `live_mode` | `single` | `single` = one session (recommended); `failover` = direct + relay sessions at once, freshest frame wins |
| `http_username` / `http_password` | `ubox` / empty | protect the page and streams (empty password = open) |

The Configuration tab wins on every restart; edits on the web page apply
immediately but only until the next restart.

**Slow hardware?** Use `stream: 0`, or keep `stream: 1` with
`max_width: 1280` and `fps: 10`. Decoding H.265 is the main CPU cost.

## Transport (auto / relay / direct)

The vendor library has no transport parameter; it picks LAN or relay by
itself. The add-on forces a path at the network layer (needs the
`NET_ADMIN` privilege, already declared):

- **Auto**: no rules, the library decides (default).
- **Relay**: blocks LAN discovery (UDP/32762), public relay only (remote /
  other subnet).
- **Direct**: blocks all P4P relays (UDP/20001), LAN only (same LAN; the
  picture stays black across networks).

Switch it on the web page (`POST /api/transport?mode=`); it is persisted and
restarts the stream (~10 s). Current mode and whether it was really applied
are reported in `/stats`.

## Status and troubleshooting

`/stats` reports totals plus a per-branch block (`branches.main`,
`video1`, `video2`) with `running`, `decoded`, `frame_age_ms`,
`first_frame_s`, `restarts`, `last_exit`, `next_start_in_s` and the last
lines of the camera library log (`rehost_log`).

The add-on log shows every start, first frame, stall and restart, e.g.:

```
branch main pipeline spawned (stream=1 fps=native q=5 width=orig)
branch main first video after 8.4s
branch main pipeline ended: stalled: no frames from camera for 20s
branch main restart in 3s
```

## Endpoints

| Path | |
| --- | --- |
| `/` | web page |
| `/video.mjpg` | main live stream (what HA should use) |
| `/video0.mjpg`, `/video1.mjpg`, `/video2.mjpg` | main / direct-only / relay-only branch |
| `/snap.jpg` | latest frame (placeholder before the first one) |
| `/stats` | JSON status |
| `/api/live/hls?file=index.m3u8` | live HLS (H.265 copy, few seconds of latency) |

## Changes in 0.8.0

Stability:

- **Camera library output is now drained.** Its stdout went to a pipe that
  nobody read; after a few minutes of per-frame logging the pipe filled up,
  the library blocked and the session died. This was the main cause of the
  stream freezing in Home Assistant while the phone app kept working.
- **One camera session instead of two.** `/video.mjpg` used to start a
  direct and a relay session at the same time — double CPU under qemu and
  two session slots on the camera. Now it's one session (`live_mode:
  single`); the old behaviour is still available as `failover`.
- **Watchdog**: if no frame arrives for `stall_timeout` seconds (or no video
  within 75 s of a cold start) the session is restarted automatically, with
  backoff (3 s → 60 s) so the camera can free its slot.
- **No more timeouts in Home Assistant**: a "Connecting to camera..." frame
  is sent immediately and repeated every second until real frames arrive,
  and whenever the camera goes quiet. HA's MJPEG proxy drops streams that
  send nothing for 10 s — exactly the length of a cold start.
- `/snap.jpg` returns a placeholder instead of 404, so HA doesn't mark the
  camera unavailable.
- Fixed a race that could spawn two pipelines on the same directory;
  pipelines are cleanly killed when the add-on stops.
- Frame files are deleted as soon as they are consumed (previously
  `/tmp` grew for up to 24 h).

Performance:

- Frames are picked up within ~10 ms (was 150 ms per missing frame plus a
  50–100 ms "stable size" wait on every frame, which capped the rate and
  let latency build up).
- Real frame rate: raw H.265 carries no timestamps, so ffmpeg assumed
  25 fps and the old `fps=8` filter on a 10–15 fps camera produced only
  ~3–5 fps. Now every frame is passed through by default (`fps: 0`), and a
  limit, when set, uses real arrival times.
- JPEGs are published as soon as ffmpeg emits them (it used to wait for
  64 KB of output, batching several frames) and pushed to viewers right
  away (no 100 ms polling).
- Low-latency decoder flags, optional downscaling, configurable quality.
- Live HLS uses real timestamps (was hardcoded at 30 fps), and can no longer
  slow down the MJPEG stream.

Other: whole UI, messages and docs in English; options exposed in the
add-on Configuration tab; built locally (no prebuilt image needed).

## Layout

```
ubox/
  config.yaml   add-on manifest (amd64/aarch64, host_network)
  Dockerfile    python:3.12-slim-bookworm + ffmpeg + qemu-aarch64-static
  run.py        supervisor: on-demand qemu → ffmpeg → MJPEG, watchdog
  bin/          rehost + lib29.so (crash-patched) helpers
  rootfs/       slim bionic (linker64 + libc/dl/m/log/stdc++/c++_shared, ~3.4 MB)
  translations/ option descriptions for the Configuration tab
```

## Limits

- Cold start to first frame is about 10–20 s (session handshake + waiting
  for an IDR frame with parameter sets).
- Stopping is SIGTERM; the camera releases its session slot on its own
  timeout. That's why restarts back off.
- Account and passwords are stored only in the add-on's `/data`, never in
  the image or the repository.
