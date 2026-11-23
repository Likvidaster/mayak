#pragma once

#include <QString>

// Mayak service (Windows): repairs the WinTun state after Windows refused to create Mayak's tunnel
// adapter (PnP problem code 31, status 0xC00002F0, tunnel service error "creating a WinTun device").
// Seen on the owner's PC when a running tunnel was cut (instant process exit in 5.1.0.25/5.1.0.26,
// an update installed over a running VPN): every later start of the fixed-GUID adapter failed until
// a reboot or until ANY other WinTun adapter was created (Browsec did it twice, 20.11.2026; same
// driver package). This does the same: one temporary adapter with a random GUID is created through
// this installation's wintun.dll and removed at once. Nothing else is touched: no routes, no
// addresses, no other adapter. Never runs while Mayak's AWG tunnel service runs; the app asks for it
// only when no tunnel of its own runs (also no Xray tunnel: it repairs before a start, after the
// previous attempt was confirmed down).
namespace MayakWintunHeal {
// "healed", "busy" (Mayak's tunnel service still runs), "no_wintun" or "create_failed".
QString run();
}
