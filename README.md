[Auth.Website](https://auth.website)
====================================

A developer tool to generate OAuth tokens from sites that don't provide an easier way.

Some sites allow developers to generate OAuth tokens easily.
* [GitHub](https://github.com/) allows developers to create
  [Personal Access Tokens](https://github.com/settings/tokens).
* [Twitter](https://twitter.com/) allows developers to create
  [Access Tokens](https://developer.twitter.com/en/docs/basics/authentication/guides/access-tokens.html)
  for apps they own.

Other sites don't have such a simple one-click solution. They expect all
tokens to be created via the normal OAuth dance.

[Auth.Website](https://auth.website) is a dynamic OAuth client that accepts
whatever client credentials you input and does the dance for you so that
you end up with a token.

Auth.Website is *not* a general solution for creating tokens from any
website. Auth.Website requires that you first create an app/client on the
website you're working with.

Using
-----

1. Create an app on the OAuth provider you're working with.
2. In Auth.Website, enter the provider's details (Authorization URL, Token
   URL) and your new app's client credentials (Client ID, Client Secret).
3. Click "Submit" and go through the OAuth dance.

Security
--------

No - this is not secure :) You shouldn't trust anyone with your
app/client's credentials. That means you shouldn't trust Auth.Website with
them! Why are you even here?
