'use strict';

module.exports = function (grunt) {

    // Load tasks from grunt-* dependencies in package.json
    require('load-grunt-tasks')(grunt);

    // Time how long tasks take
    require('time-grunt')(grunt);

    // Project configuration
    grunt.initConfig({
        exec: {
            emscripten: {
                cmd: function (arch) {
                    if (typeof arch === 'undefined') {
                        return 'python build.py'
                    } else {
                        return 'python build.py ' + arch;
                    }
                }
            }
        },
        uglify: {
            dist: {
                options: {
                    compress: true,
                },
                files: {
                    'dist/capstone.min.js': [
                        'src/**/*.js'
                    ]
                }
            }
        },
        connect: {
            options: {
                port: 9001,
                livereload: 35729,
                hostname: 'localhost'
            },
            livereload: {
                options: {
                    open: true
                }
            }
        },
        watch: {
            livereload: {
                files: [
                    'index.html',
                    'dist/*.js'
                ],
                options: {
                    livereload: '<%= connect.options.livereload %>'
                }
            },
        }
    });

    // Project tasks
    grunt.registerTask('build', 'Build for specific architecture', function (arch) {
        if (typeof arch === 'undefined') {
            grunt.config.set('lib.suffix', '');
            grunt.task.run('exec:emscripten');
            grunt.task.run('uglify');
        } else {
            grunt.config.set('lib.suffix', '-'+arch);
            grunt.task.run('exec:emscripten:'+arch);
            grunt.task.run('uglify');
        }
    });
    grunt.registerTask('release', [
        'build',
        'build:arm',
        'build:arm64',
        'build:mips',
        'build:ppc',
        'build:sparc',
        'build:sysz',
        'build:x86',
        'build:xcore',
    ]);
    grunt.registerTask('serve', [
        'connect',
        'watch'
    ]);
};
