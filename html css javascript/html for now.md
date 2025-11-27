### [Opening links in a new tab](https://www.theodinproject.com/lessons/foundations-links-and-images#opening-links-in-a-new-tab)

The method shown above opens links in the same tab as the webpage containing them. This is the default behavior of most browsers and it can be changed relatively easily. All we need is another attribute: the `target` attribute.

While `href` specifies the destination link, `target` specifies where the linked resource will be opened. If it is not present, then, by default, it will take on the `_self` value which opens the link in the current tab. To open the link in a new tab or window (depends on browser settings) you can set it to `_blank` as follows:

```html
<a href="https://www.theodinproject.com/about" target="_blank" rel="noopener noreferrer">About The Odin Project</a>
```

You may have noticed that we snuck in the `rel` attribute above. This attribute is used to describe the relation between the current page and the linked document.

`noopener`: The `noopener` value of the `rel` attribute ensures that a link opened in a new tab or window cannot interact with or access the original page. Without it, the new page can use JavaScript to manipulate the original page, which poses a security risk.

For example:

```html
<a href="https://example.com" target="_blank" rel="noopener">Open Example</a>
```

In this code: target=”_blank”: opens the link in a new tab. rel=”noopener”: prevents the new tab from accessing the original page, ensuring security. Without `noopener`, the new tab could use JavaScript to interact with the original page, which is unsafe.

`noreferrer`: The `noreferrer` value of the `rel` attribute provides both privacy and security. It prevents the new page from knowing where the user came from (hiding the referrer) and also includes the behavior of `noopener`, preventing the new page from accessing the original page.

For example:

```html
<a href="https://example.com" target="_blank" rel="noreferrer">Visit Example</a>
```

In this example: target=”_blank”: opens the link in a new tab. rel=”noreferrer”: ensures the new page cannot see the referring page’s address (privacy) and prevents it from accessing the original page (security).

By using rel=”noreferrer”, you automatically get the benefits of both privacy and security.

Why do we need this added behavior for opening links in new tabs? Security reasons. The prevention of access that is caused by `noopener` prevents [phishing attacks](https://www.ibm.com/topics/phishing) where the opened link may change the original webpage to a different one to trick users. This is referred to as [tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing). Adding the `noreferrer` value can be done if you wish to not let the opened link know that your webpage links to it.

Note that you may be fine if you forget to add `rel="noopener noreferrer"` since more recent versions of browsers [provide security](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#security_and_privacy) if only `target="_blank"` is present. Nevertheless, in line with good coding practices and to err on the side of caution, it is recommended to always pair a `target="_blank"` with a `rel="noreferrer"` (which also includes `noopener`).

### [Absolute and relative links](https://www.theodinproject.com/lessons/foundations-links-and-images#absolute-and-relative-links)

Generally, there are two kinds of links we will create:

- Links to pages on other websites on the internet.
- Links to pages located on our own websites.

#### [Absolute links](https://www.theodinproject.com/lessons/foundations-links-and-images#absolute-links)

Links to pages on other websites on the internet are called absolute links. A typical absolute link will be made up of the following parts: `scheme://domain/path`. An absolute link will always contain the [scheme and domain](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Web_mechanics/What_is_a_URL#basics_anatomy_of_a_url) of the destination.

We’ve already seen an absolute link in action. The link we created to The Odin Project’s About page earlier was an absolute link as it contains the scheme and domain.

`https://www.theodinproject.com/about`

#### [Relative links](https://www.theodinproject.com/lessons/foundations-links-and-images#relative-links)

Links to other pages within our own website are called relative links. Relative links do not include the domain name, since it is another page on the same site, it assumes the domain name will be the same as the page we created the link on.

Relative links only include the file path to the other page, _relative_ to the page you are creating the link on. This is quite abstract, let’s see this in action using an example.

Within the `odin-links-and-images` directory, create another HTML file named `about.html` and paste the following code into it:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Odin Links and Images</title>
  </head>

  <body>
    <h1>About Page</h1>
  </body>
</html>
```

Back in the index page, add the following anchor element to create a link to the about page:

```html
<body>
  <h1>Homepage</h1>
  <a href="https://www.theodinproject.com/about">About The Odin Project</a>

  <a href="about.html">About</a>
</body>
```

Open the index file in a browser and click on the about link to make sure it is all wired together correctly. Clicking the link should go to the about page we just created.

This works because the index and about page are in the same directory. That means we can use its name (`about.html`) as the link’s `href` value.

But we will usually want to organize our website directories a little better. Normally we would only have the `index.html` at the root directory and all other HTML files in their own directory.

Create a directory named `pages` within the `odin-links-and-images` directory and move the `about.html` file into this new directory.

Refresh the index page in the browser and then click on the about link. It will now be broken. This is because the location of the about page file has changed.

To fix this, we just need to update the about link `href` value to include the `pages/` directory since that is the new location of the about file _relative_ to the index file.

```html
<body>
  <h1>Homepage</h1>
  <a href="pages/about.html">About</a>
</body>
```

Refresh the index page in the browser and try clicking the about link again, it should now be back in working order.

In many cases, this will work just fine; however, you can still run into unexpected issues with this approach. Prepending `./` before the link will in most cases prevent such issues. By adding `./` you are specifying to your code that it should start looking for the file/directory _relative_ to the `current` directory.

```html
<body>
  <h1>Homepage</h1>
  <a href="./pages/about.html">About</a>
</body>
```

#### [A metaphor](https://www.theodinproject.com/lessons/foundations-links-and-images#a-metaphor)

Absolute and relative links are a tricky concept to build a good mental model of, a metaphor may help:

Think of your domain name (`town.com`) as a town, the directory in which your website is located (`/museum`) as a museum, and each page on your website as a room in the museum (`/museum/movie_room.html` and `/museum/shops/coffee_shop.html`). Relative links like `./shops/coffee_shop.html` are directions from the current room (the museum movie room `/museum/movie_room.html`) to another room (the museum shop). Absolute links, on the other hand, are full directions including the protocol (`https`), domain name (`town.com`) and the path from that domain name (`/museum/shops/coffee_shop.html`): `https://town.com/museum/shops/coffee_shop.html`.

### [Images](https://www.theodinproject.com/lessons/foundations-links-and-images#images)

Websites would be fairly boring if they could only display text. Luckily HTML provides a wide variety of elements for displaying all sorts of different media. The most widely used of these is the image element.

To display an image in HTML we use the `<img>` element. Unlike the other elements we have encountered, the `<img>` element is a void element. As we have seen earlier in the course, void elements do not need a closing tag because they are naturally empty and do not contain any content.

Instead of wrapping content with an opening and closing tag, it embeds an image into the page using a `src` attribute which tells the browser where the image file is located. The `src` attribute works much like the `href` attribute for anchor tags. It can embed an image using both absolute and relative paths.

For example, using an absolute path we can display an image located on The Odin Project site:

To display images on your website that are hosted on your own web server, you can use a relative path.

Linux, macOS, ChromeOS

1. Create a new directory named `images` within the `odin-links-and-images` project.
2. Next, [download our practice image](https://unsplash.com/photos/Mv9hjnEUHR4/download?force=true&w=640) and move it into the images directory we just created.
3. Rename the image to `dog.jpg`.

WSL2

When you download a file from the internet, Windows has a security feature that creates a hidden `Zone.Identifier` file with the same name as your downloaded file and it looks like `mypicture.jpg:Zone.Identifier` This file is harmless, but we’d like to avoid copying it over and cluttering up our directories.

1. Create a new directory named `images` within the `odin-links-and-images` project.
    
2. Next, [download the stock dog image](https://unsplash.com/photos/Mv9hjnEUHR4/download?force=true&w=640).
    
3. Right click on the new download at the bottom of the chrome window and select “Show in folder”.
    
    1. Alternatively, if you do not see anything at the bottom of the chrome window, open the “Customize and control Google Chrome kebab menu and select the “Downloads” item. This will show all of your downloads, each with its own “Show in folder” button.
4. Rename the image to `dog.jpg`.
    
5. Drag the file from your downloads folder to VSCode’s file browser into your new `images` directory.
    
    1. Alternatively, using your Ubuntu terminal, navigate to the folder you want to copy the image to (`cd ~/odin-links-and-images` for example)
        
    2. Type `cp <space>`
        
    3. Drag the `dog.jpg` image from a Windows Explorer window and drop it onto the terminal window, it should appear as `"/mnt/c/users/username/Downloads/dog.jpg"`
        
    4. Type `<space> .` to tell cp that you want to copy the file to your current working directory. The full command will look something like:
        
    
    ```bash
    cp "/mnt/c/users/username/Downloads/dog.jpg" .
    ```
    
    1. Hit Enter to complete the command, and use `ls` to confirm the file now exists.

Dragging files from Windows into the VSCode file browser prevents the `Zone.Identifier` files from being copied over. From now on, any time you need to copy pictures or other downloaded files like this into WSL2, you can do it in this way. If you ever accidentally copy these `Zone.Identifier` files into WSL2, you can safely delete them without any issue.

Finally add the image to the `index.html` file:

```html
<body>
  <h1>Homepage</h1>
  <a href="https://www.theodinproject.com/about">About The Odin Project</a>

  <a href="./pages/about.html">About</a>

  <img src="./images/dog.jpg">
</body>
```

Save the `index.html` file and open it in a browser to view Charles in all his glory.

#### [Images you use should be free for your intended purpose](https://www.theodinproject.com/lessons/foundations-links-and-images#images-you-use-should-be-free-for-your-intended-purpose)

There are many free images available but make sure to give credit to the creator of the image in your project.

An easy way to provide credit is to include the creator’s name and contact info in a README file in your repository, or give [attribution](https://support.freepik.com/s/article/Attribution-How-when-and-where?language=en_US).

To find them - Google images and in image results -> Tools -> Usage rights -> “Creative Commons”. Choose & click on a image and click license details.

We recommend that you always review the license requirements of any images you want to use.

### [Parent directories](https://www.theodinproject.com/lessons/foundations-links-and-images#parent-directories)

What if we want to use the dog image in the about page? We would first have to go up one level out of the pages directory into its parent directory so we could then access the images directory.

To go to the parent directory we need to use two dots in the relative filepath like this: `../`. Let’s see this in action, within the body of the `about.html` file, add the following image below the heading we added earlier:

```html
<img src="../images/dog.jpg">
```

To break this down:

1. First, we are going to the parent directory of the `pages` directory which is `odin-links-and-images`.
2. Then, from the parent directory, we can go into the `images` directory.
3. Finally, we can access the `dog.jpg` file.

Using the metaphor we used earlier, using `../` in a filepath is kind of like stepping out from the room you are currently in to the main hallway so you can go to another room.

### [Alt attribute](https://www.theodinproject.com/lessons/foundations-links-and-images#alt-attribute)

Besides the `src` attribute, every image element should also have an `alt` (alternative text) attribute.

The `alt` attribute is used to describe an image. It will be used in place of the image if it cannot be loaded. It is also used with screen readers to describe what the image is to visually impaired users.

This is how the The Odin Project logo example we used earlier looks with an `alt` attribute included:

As a bit of practice, add an `alt` attribute to the dog image we added to the `odin-links-and-images` project.

### [Image size attributes](https://www.theodinproject.com/lessons/foundations-links-and-images#image-size-attributes)

While not strictly required, specifying height and width attributes in image tags helps the browser layout the page without causing the page to jump and flash.

It is a good habit to always specify these attributes on every image, even when the image is the correct size or you are using CSS to modify it. This is to prevent content jumping as images load. Use the image’s actual dimensions when specifying size.

Here is our Odin Project logo example with height and width attributes included:

Go ahead and update the `odin-links-and-images` project with width and height attributes on the dog image.