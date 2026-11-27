'use strict';
/**
 * Create-or-update ONE sticky pull request comment (marker `<!-- deployready -->`).
 * Called from actions/github-script: require(...)({ github, context, core }).
 */
const fs = require('fs');
const { MARKER } = require('./summary');

module.exports = async function upsertComment({ github, context, core }, file) {
  const body = fs.readFileSync(file || process.env.DR_SUMMARY_FILE, 'utf8');
  const pr = context.payload && context.payload.pull_request;
  if (!pr) return;
  const { owner, repo } = context.repo;
  const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number: pr.number, per_page: 100 });
  const existing = comments.find((c) => typeof c.body === 'string' && c.body.includes(MARKER));
  try {
    if (existing) await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
    else await github.rest.issues.createComment({ owner, repo, issue_number: pr.number, body });
  } catch (err) {
    // Fork PRs get a read-only token; the job summary still has the result.
    core.warning(`Could not post the PR comment: ${err.message}`);
  }
};
