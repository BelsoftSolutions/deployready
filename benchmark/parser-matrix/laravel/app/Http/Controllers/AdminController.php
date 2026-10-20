<?php

namespace App\Http\Controllers;

class AdminController extends Controller
{
    public function stats() { return ['users' => 0]; }
    public function destroy($id) { return response()->noContent(); }
}
