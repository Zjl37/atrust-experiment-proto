import tkinter as tk
from PIL import Image, ImageTk
from io import BytesIO

"""
CAPTCHA solver (manually pick points...)
"""

def pick_points(image_buffer, num_points=3, display_width=800):
    # img = Image.open(image_path)
    img = Image.open(BytesIO(image_buffer))
    orig_width, orig_height = img.width, img.height

    scale = orig_width / display_width
    new_size = (int(orig_width / scale), int(orig_height / scale))
    img = img.resize(new_size)

    root = tk.Tk()
    tk_img = ImageTk.PhotoImage(img)
    canvas = tk.Canvas(root, width=img.width, height=img.height)
    canvas.pack()
    canvas.create_image(0, 0, anchor="nw", image=tk_img)

    coordinates = []

    def on_click(event):
        x = int(event.x * scale)
        y = int(event.y * scale)
        canvas.create_oval(
            event.x - 5, event.y - 5, event.x + 5, event.y + 5, fill="red"
        )
        coordinates.append([x, y])
        print([x, y])
        if len(coordinates) >= num_points:
            root.after(1000, root.destroy)

    canvas.bind("<Button-1>", on_click)
    root.mainloop()

    return {"coordinates": coordinates, "width": orig_width, "height": orig_height}


if __name__ == "__main__":
    with open("CheckCode.jpg", "rb") as f:
        image_buffer = f.read()

    result = pick_points(image_buffer, num_points=3)

    import json

    print(json.dumps(result, separators=(",", ":")))
