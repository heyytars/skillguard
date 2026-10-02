import sys
from playwright.sync_api import sync_playwright

src, dst = sys.argv[1], sys.argv[2]
with sync_playwright() as p:
    b = p.chromium.launch(
        executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", headless=True
    )
    pg = b.new_page(device_scale_factor=2, viewport={"width": 1300, "height": 1000})
    pg.goto("file://" + src)
    pg.wait_for_timeout(400)
    pg.locator("#art").screenshot(path=dst, omit_background=True)
    b.close()
print("wrote", dst)
