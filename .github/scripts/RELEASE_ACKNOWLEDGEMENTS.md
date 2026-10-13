# Release acknowledgements

GitHub tag releases append a bilingual `致谢 / Thanks` section after GoReleaser publishes the release. The current changelog groups and support footer are preserved.

The generator reads complete commit messages in the release range, resolves local `#123`, `owner/repo#123`, and GitHub issue/PR URLs, then credits:

- Authors of referenced issues, whether open or closed.
- Authors of referenced merged pull requests.
- Authors of issues referenced in those PR titles/bodies or linked through GitHub's `closingIssuesReferences` connection, including links added through the GitHub UI.

It does not recursively follow references in issue bodies or credit all commenters. References to other repositories are excluded. Bots, the repository owner, and the workflow's `exclude` accounts are omitted. Accounts are grouped and sorted; individual issue/PR links show the source of each acknowledgement.

For stable tags (`vX.Y.Z`), the baseline is the preceding reachable stable tag, so work released in intervening betas is included. For beta and other `v*` tags, it is the preceding reachable version tag. The first release includes the available history. `git describe` follows the checked-out tag's ancestry rather than GitHub's `latest` release, because this repository also publishes beta tags without the prerelease flag.

The module uses the authenticated GitHub client supplied by `actions/github-script@v7`. `contents: write`, `issues: read`, and `pull-requests: read` are declared in the workflow. Network access is limited to the GitHub Actions release job; the SamWaf application gains no outbound requests or runtime dependencies.

The generated list also appears in the Actions job summary, where it can be copied into manually edited release notes or the documentation changelog. The generated section is delimited by HTML comments. Running the step again replaces that section while preserving other release text. GoReleaser's existing `mode: append` behavior for the main changelog is independent of this section. If GitHub data cannot be resolved, the step reports an error and leaves release notes unchanged; `continue-on-error` allows the package release to finish. Inspect the `Add release acknowledgements` step if the section is absent.

To ensure a report is credited, include its issue number in the implementation commit or the merged PR description. For example:

```text
fix: read cached failure records type-safely across cache backends

#1002
```

Gitee identifiers, offline reports, and contributions without recorded links remain manual. The generator does not edit the documentation site's `Update.md` files. Manual additions to a release should go outside the generated marker block. If you replace the entire release body with documentation content after publication, copy the generated acknowledgements block into that content as well.

Run the offline verification suite from the repository root:

```sh
node --test .github/scripts/release_acknowledgements.test.cjs
```

The test suite covers reference parsing, issue attribution behind maintainer PRs, deduplication, bot exclusions, GraphQL pagination, unmerged PR exclusion, incomplete API resolution, idempotent notes editing, and real temporary Git histories for stable/beta baselines. It never updates a live release.

References:

- [GitHub automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes)
- [GoReleaser changelog](https://goreleaser.com/customization/changelog/)
- [GitHub GraphQL objects](https://docs.github.com/en/graphql/reference/objects)
