
```markdown
# 🖱️⏳ ShareMouse Free Work

**Seamlessly share your mouse and keyboard across iOS, Mac, and Windows.**

Tired of juggling multiple keyboards and mice? ShareMouse Free Work lets you control multiple devices with a single set of peripherals. Turn your iPhone or iPad into a wireless trackpad, or move your cursor seamlessly between your Mac and Windows PC using edge-triggering. 

---

## 📸 App Preview

| iOS Remote Control | Windows Client | Mac Server / Client |
| :---: | :---: | :---: |
| [https://github.com/alsh3la/ShareMouse-Free-Vibe-coding-/blob/main/assets/MAC.jpeg](https://raw.githubusercontent.com/alsh3la/ShareMouse-Free-Vibe-coding-/main/assets/MAC.jpeg) |

---

## ✨ Key Features

- **Cross-Platform Support:** Works flawlessly across iOS, macOS, and Windows.
- **iOS as a Remote Trackpad:** Use your iPhone/iPad as a highly responsive wireless mouse and keyboard for your computer.
- **Server/Client Architecture:** Flexible setup. Designate one machine as the Server (host) and others as Clients, or use your iOS device strictly as an input remote.
- **Edge-Trigger Hand-Off:** Move your cursor to the edge of your screen, and it magically appears on your next monitor/device.
- **Privacy & Security Controls:** Lock your mouse or keyboard remotely, and pause connections without terminating them to ensure privacy when needed.
- **Media & Keyboard Controls:** Quick access to keyboard input and media playback controls directly from the iOS app.

---

## 📱 iOS Touch Gestures

The iOS app provides an intuitive touch interface simulating a standard mouse. Here are the default controls on the **Basic Input** screen:

| Gesture | Action |
| :--- | :--- |
| 👆 **One-finger tap** | Left Click |
| ✌️ **Two-finger tap** | Right Click |
| 👆👆 **Two-finger drag** | Scroll |
| 🤏 **Pinch** | Zoom In / Out |
| ✊ **Long press & drag** | Drag items (Click & Hold) |
| ✊👆 **Long press, drag, then tap** | Drop / Release items |

---

## ⚙️ How It Works

ShareMouse uses a standard **Server / Client** networking model over your local Wi-Fi network.

1. **Server Mode:** Choose this for the machine that has the physical mouse and keyboard attached. (e.g., your Mac). The cursor will leave this screen to travel to client devices.
2. **Client Mode:** Choose this for the machine you want to control remotely (e.g., your Windows PC). It receives the input sent from the Server. 
3. **iOS Remote Mode:** Connect your iOS device to the Server IP to use it as a remote trackpad/keyboard.

---

## 🚀 Getting Started

### Prerequisites
- All devices must be connected to the **same Wi-Fi network**.
- Ensure your firewall allows ShareMouse to communicate over the local network.

### Installation

1. **macOS / Windows:** Download the latest release from the [Releases](../../releases) page and install it on your host/client machines.
2. **iOS:** Download ShareMouse Free Work from the App Store on your iPhone or iPad.

### Quick Setup Guide

1. Launch ShareMouse on your Mac/PC. 
2. On your main computer, select **SERVER**. The app will display your local IP address (e.g., `192.168.x.x`).
3. On your secondary computer, select **CLIENT** and enter the Server IP address.
4. Open the iOS app, enter the Server IP, and start swiping to control!
5. (Optional) Enable **Edge-trigger hand-off** on your clients to move the cursor seamlessly between physical monitors.

---

## 🛡️ Status Controls

Easily manage your connections via the bottom control panel on the desktop:
- **Resume / Pause:** Keep the connection alive but suspend input (Great for temporary privacy).
- **Lock Mouse / Lock Keyboard:** Block specific inputs from being transmitted.
- **Stop:** Completely sever the connection.
- **Tray:** Minimize the app to the system tray/background.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [Issues page](../../issues).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
