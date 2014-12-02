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
                command: 'python build.py'
            }
        },
        uglify: {
            dist: {
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
                hostname: 'localhost',
                base: 'dist'
            },
            livereload: {
                options: {
                    open: true
                }
            }
        },
        watch: {
            scripts: {
                files: 'src/**/*.ts',
                tasks: ['typescript']
            },
            livereload: {
                files: [
                    'dist/**/*.html',
                    'dist/*.js',
                    'dist/*.css'
                ],
                options: {
                    livereload: '<%= connect.options.livereload %>'
                }
            },
        }
    });

    // Project tasks
    grunt.registerTask('test', [

    ]);
    grunt.registerTask('build', [
        'exec:emscripten',
        'uglify'
    ]);
    grunt.registerTask('default', [
        'test',
        'build'
    ]);
};
