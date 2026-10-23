# Publishing the Wiki

The canonical wiki source lives in `docs/wiki/` so documentation changes can be reviewed with code. The directory also follows GitHub Wiki conventions: `Home.md` is the landing page and `_Sidebar.md` defines navigation.

## Publish to GitHub Wiki

Enable the repository Wiki, then clone its separate Git repository:

```sh
git clone https://github.com/privometry/privometry-oss.wiki.git /tmp/privometry-oss-wiki
```

Synchronize Markdown files from a clean checkout:

```sh
rsync -av --delete docs/wiki/ /tmp/privometry-oss-wiki/
git -C /tmp/privometry-oss-wiki status
git -C /tmp/privometry-oss-wiki add .
git -C /tmp/privometry-oss-wiki commit -m "Sync developer wiki"
git -C /tmp/privometry-oss-wiki push
```

Review the `--delete` preview and destination before publishing. The repository copy remains authoritative.

## Editing rules

- Use relative links between wiki pages.
- Keep page filenames stable after publication because external links may depend on them.
- Put code behavior and flags in the same pull request as their documentation changes.
- Avoid customer names, internal URLs, tokens, screenshots containing data, or unpublished security details.
- Verify links and command examples before syncing.

## Suggested automation

A future workflow can publish `docs/wiki/` after changes merge to `main`. Use a narrowly scoped credential, protect the Wiki branch, and require the same documentation review that applies to repository changes.
