# Listing PosturaNet in the GitHub Marketplace and the Claude plugin directory

Both listings need the repo owner's own account, so they are the founder's clicks. Everything
the listings read is already in the repo.

## GitHub Action (GitHub Marketplace)

What's ready: `action.yml` at the repo root is the one Marketplace lists (`action/action.yml` is
the same Action for `uses: Mihirajmera/posturanet/action@<tag>`). Its name, `PosturaNet`, is not
taken by another Marketplace action, user or organization (checked 2026-11-24). The description
is 125 characters, with `shield` / `green` branding.

Once, on the account that owns the repo:
1. Turn on two-factor authentication if it isn't on.
2. Accept the GitHub Marketplace Developer Agreement (the publish checkbox stays greyed out until
   you do; GitHub offers it the first time you try).

Each release you want listed:
1. Open `action.yml` on GitHub; the banner offers **Draft a release**. Or open an existing tag's
   release and choose **Edit**.
2. Tick **Publish this Action to the GitHub Marketplace** and wait for "Everything looks good!".
3. Primary category: **Security**. Another category: **Continuous integration**.
4. Pick the tag (for example `v0.5.1`), keep the release notes from the CHANGELOG, and click
   **Publish release** (or **Update release**).

Listing is immediate; GitHub doesn't review it.

## Claude plugin

Anyone can already install it from this repo's own marketplace:

```
/plugin marketplace add Mihirajmera/posturanet
/plugin install posturanet@posturanet
```

`claude plugin validate ./plugin --strict` and `claude plugin validate . --strict` pass.

To be listed in Anthropic's plugin directory (claude.ai, Cowork and Claude Code):
1. Sign in to claude.ai with a paid plan and open the developer portal at
   <https://claude.ai/directory/manage>.
2. Work through Anthropic's pre-submission checklist
   (<https://claude.com/docs/plugins/pre-submission-checklist>).
3. Submit the plugin from the GitHub repo `Mihirajmera/posturanet` (plugin folder `plugin/`).
   Anthropic reviews it; the portal checks more than the local validator does.

The default `claude-plugins-official` marketplace takes no submissions; Anthropic adds plugins to
it at its own discretion.
