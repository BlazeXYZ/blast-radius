// Deliberately outdated demo projects: each pin is a real version with a real story.

export const EXAMPLES = {
  npm: {
    filename: 'package.json',
    text: JSON.stringify(
      {
        name: 'legacy-node-app',
        version: '1.0.0',
        dependencies: {
          express: '4.16.0',
          lodash: '4.17.15',
          request: '2.88.0',
          moment: '2.24.0',
          jsonwebtoken: '8.5.1',
          axios: '0.21.0',
          'node-sass': '4.14.1',
          'event-stream': '3.3.6',
          'left-pad': '1.3.0',
          minimist: '1.2.0',
        },
      },
      null,
      2,
    ),
  },
  pypi: {
    filename: 'requirements.txt',
    text: [
      '# A Flask service nobody has touched since 2019',
      'flask==1.0',
      'jinja2==2.10',
      'requests==2.19.0',
      'urllib3==1.24.1',
      'django==2.2.0',
      'pyyaml==5.3',
      'pillow==8.0.0',
      'cryptography==3.2',
      'celery[redis]==4.4.0',
    ].join('\n'),
  },
};
